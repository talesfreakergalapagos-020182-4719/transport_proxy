//go:build windows

package sspi

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modSecur32 = syscall.NewLazyDLL("secur32.dll")

	procAcquireCredentialsHandleW  = modSecur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContextW = modSecur32.NewProc("InitializeSecurityContextW")
	procAcceptSecurityContext      = modSecur32.NewProc("AcceptSecurityContext")
	procCompleteAuthToken          = modSecur32.NewProc("CompleteAuthToken")
	procDeleteSecurityContext      = modSecur32.NewProc("DeleteSecurityContext")
	procFreeCredentialsHandle      = modSecur32.NewProc("FreeCredentialsHandle")
	procFreeContextBuffer          = modSecur32.NewProc("FreeContextBuffer")
)

const (
	SECBUFFER_VERSION = 0
	SECBUFFER_EMPTY   = 0
	SECBUFFER_DATA    = 1
	SECBUFFER_TOKEN   = 2

	SECPKG_CRED_INBOUND  = 0x00000001
	SECPKG_CRED_OUTBOUND = 0x00000002

	SECURITY_NATIVE_DREP = 0x00000010

	ISC_REQ_DELEGATE        = 0x00000001
	ISC_REQ_MUTUAL_AUTH     = 0x00000002
	ISC_REQ_REPLAY_DETECT   = 0x00000004
	ISC_REQ_SEQUENCE_DETECT = 0x00000008
	ISC_REQ_CONFIDENTIALITY = 0x00000010
	ISC_REQ_USE_SESSION_KEY = 0x00000020
	ISC_REQ_ALLOCATE_MEMORY = 0x00000100
	ISC_REQ_CONNECTION      = 0x00000800

	ASC_REQ_DELEGATE        = 0x00000001
	ASC_REQ_MUTUAL_AUTH     = 0x00000002
	ASC_REQ_REPLAY_DETECT   = 0x00000004
	ASC_REQ_SEQUENCE_DETECT = 0x00000008
	ASC_REQ_CONFIDENTIALITY = 0x00000010
	ASC_REQ_USE_SESSION_KEY = 0x00000020
	ASC_REQ_ALLOCATE_MEMORY = 0x00000100
	ASC_REQ_CONNECTION      = 0x00000800

	SEC_E_OK                    = 0x00000000
	SEC_I_CONTINUE_NEEDED       = 0x00090312
	SEC_I_COMPLETE_NEEDED       = 0x00090313
	SEC_I_COMPLETE_AND_CONTINUE = 0x00090314
)

// SecHandle is used for both CredHandle and CtxtHandle.
type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

// TimeStamp represents Windows FILETIME / LARGE_INTEGER.
type TimeStamp struct {
	LowPart  uint32
	HighPart int32
}

// SecBuffer represents a buffer in SSPI.
type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   unsafe.Pointer
}

// SecBufferDesc describes an array of SecBuffer structures.
type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *SecBuffer
}

// SSPIContext encapsulates the state of an ongoing SSPI authentication handshake.
type SSPIContext struct {
	authPackage string
	targetSPN   *uint16
	credHandle  SecHandle
	ctxtHandle  SecHandle
	hasCred     bool
	hasCtxt     bool
	completed   bool
}

// NewSSPIContext creates a new SSPI context for the current Windows user session.
// packageType can be "Negotiate" (default, supports Kerberos & NTLM fallback), "NTLM", or "Kerberos".
func NewSSPIContext(packageType string, spn string) (*SSPIContext, error) {
	if packageType == "" {
		packageType = "Negotiate"
	}

	pkgPtr, err := syscall.UTF16PtrFromString(packageType)
	if err != nil {
		return nil, fmt.Errorf("invalid package name: %w", err)
	}

	ctx := &SSPIContext{
		authPackage: packageType,
	}

	if spn != "" {
		spnPtr, err := syscall.UTF16PtrFromString(spn)
		if err == nil {
			ctx.targetSPN = spnPtr
		}
	}

	var expiry TimeStamp
	r, _, _ := procAcquireCredentialsHandleW.Call(
		0,                                        // pszPrincipal (nil = current user)
		uintptr(unsafe.Pointer(pkgPtr)),          // pszPackage
		SECPKG_CRED_OUTBOUND,                     // fCredentialUse
		0,                                        // pvLogonID
		0,                                        // pAuthData (nil = default logged-on credentials)
		0,                                        // pGetKeyFn
		0,                                        // pvGetKeyArgument
		uintptr(unsafe.Pointer(&ctx.credHandle)), // phCredential
		uintptr(unsafe.Pointer(&expiry)),         // ptsExpiry
	)

	status := int32(r)
	if status != SEC_E_OK {
		return nil, fmt.Errorf("AcquireCredentialsHandle failed with status 0x%08X", uint32(status))
	}

	ctx.hasCred = true
	return ctx, nil
}

// NextStep processes the incoming server challenge token (if any) and returns the client response token.
// If serverToken is empty/nil, it generates the initial Negotiate/NTLM Type 1 token.
func (ctx *SSPIContext) NextStep(serverTokenBase64 string) (clientToken string, done bool, err error) {
	if !ctx.hasCred {
		return "", false, fmt.Errorf("SSPI context is not initialized with credentials")
	}

	var inDesc *SecBufferDesc
	var inSecBuffer SecBuffer
	var rawServerToken []byte

	if serverTokenBase64 != "" {
		rawServerToken, err = base64.StdEncoding.DecodeString(serverTokenBase64)
		if err != nil {
			return "", false, fmt.Errorf("failed to decode base64 server token: %w", err)
		}

		inSecBuffer = SecBuffer{
			cbBuffer:   uint32(len(rawServerToken)),
			BufferType: SECBUFFER_TOKEN,
			pvBuffer:   unsafe.Pointer(&rawServerToken[0]),
		}
		inDesc = &SecBufferDesc{
			ulVersion: SECBUFFER_VERSION,
			cBuffers:  1,
			pBuffers:  &inSecBuffer,
		}
	}

	outSecBuffer := SecBuffer{
		cbBuffer:   0,
		BufferType: SECBUFFER_TOKEN,
		pvBuffer:   nil,
	}
	outDesc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  &outSecBuffer,
	}

	var reqFlags uint32 = ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY
	var contextAttr uint32
	var expiry TimeStamp

	var pInCtxt uintptr
	pOutCtxt := uintptr(unsafe.Pointer(&ctx.ctxtHandle))
	var pTargetName uintptr
	var pCred uintptr
	if ctx.hasCtxt {
		pCred = 0
		pInCtxt = uintptr(unsafe.Pointer(&ctx.ctxtHandle))
		pTargetName = 0 // Must be NULL on subsequent calls
	} else {
		pCred = uintptr(unsafe.Pointer(&ctx.credHandle))
		pTargetName = uintptr(unsafe.Pointer(ctx.targetSPN))
	}

	r, _, _ := procInitializeSecurityContextW.Call(
		pCred,                                 // phCredential
		pInCtxt,                               // phContext
		pTargetName,                           // pszTargetName
		uintptr(reqFlags),                     // fContextReq
		0,                                     // Reserved1
		SECURITY_NATIVE_DREP,                  // TargetDataRep
		uintptr(unsafe.Pointer(inDesc)),       // pInput
		0,                                     // Reserved2
		pOutCtxt,                              // phNewContext
		uintptr(unsafe.Pointer(&outDesc)),     // pOutput
		uintptr(unsafe.Pointer(&contextAttr)), // pfContextAttr
		uintptr(unsafe.Pointer(&expiry)),      // ptsExpiry
	)

	status := int32(r)
	if ctx.ctxtHandle.dwLower != 0 || ctx.ctxtHandle.dwUpper != 0 {
		ctx.hasCtxt = true
	}

	// Handle completion tokens if requested
	if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		procCompleteAuthToken.Call(
			uintptr(unsafe.Pointer(&ctx.ctxtHandle)),
			uintptr(unsafe.Pointer(&outDesc)),
		)
		if status == SEC_I_COMPLETE_NEEDED {
			status = SEC_E_OK
		} else {
			status = SEC_I_CONTINUE_NEEDED
		}
	}

	var rawOutToken []byte
	if outSecBuffer.cbBuffer > 0 && outSecBuffer.pvBuffer != nil {
		rawOutToken = make([]byte, outSecBuffer.cbBuffer)
		src := unsafe.Slice((*byte)(outSecBuffer.pvBuffer), outSecBuffer.cbBuffer)
		copy(rawOutToken, src)

		// Free SSPI-allocated buffer
		procFreeContextBuffer.Call(uintptr(outSecBuffer.pvBuffer))
	}

	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
		return "", false, fmt.Errorf("InitializeSecurityContext failed with status 0x%08X", uint32(status))
	}

	if len(rawOutToken) > 0 {
		clientToken = base64.StdEncoding.EncodeToString(rawOutToken)
	}

	if status == SEC_E_OK {
		ctx.completed = true
		return clientToken, true, nil
	}

	return clientToken, false, nil
}

// Release releases all allocated SSPI handles and resources.
func (ctx *SSPIContext) Release() {
	if ctx == nil {
		return
	}
	if ctx.hasCtxt {
		procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&ctx.ctxtHandle)))
		ctx.hasCtxt = false
	}
	if ctx.hasCred {
		procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&ctx.credHandle)))
		ctx.hasCred = false
	}
}

// ServerSSPIContext encapsulates the server-side state of an SSPI handshake (for mock_proxy / test servers).
type ServerSSPIContext struct {
	authPackage string
	credHandle  SecHandle
	ctxtHandle  SecHandle
	hasCred     bool
	hasCtxt     bool
	completed   bool
}

// NewServerSSPIContext initializes an inbound server SSPI context.
func NewServerSSPIContext(packageType string) (*ServerSSPIContext, error) {
	if packageType == "" {
		packageType = "Negotiate"
	}

	pkgPtr, err := syscall.UTF16PtrFromString(packageType)
	if err != nil {
		return nil, fmt.Errorf("invalid package name: %w", err)
	}

	ctx := &ServerSSPIContext{
		authPackage: packageType,
	}

	var expiry TimeStamp
	r, _, _ := procAcquireCredentialsHandleW.Call(
		0,                                        // pszPrincipal
		uintptr(unsafe.Pointer(pkgPtr)),          // pszPackage
		SECPKG_CRED_INBOUND,                      // fCredentialUse (Inbound server)
		0,                                        // pvLogonID
		0,                                        // pAuthData
		0,                                        // pGetKeyFn
		0,                                        // pvGetKeyArgument
		uintptr(unsafe.Pointer(&ctx.credHandle)), // phCredential
		uintptr(unsafe.Pointer(&expiry)),         // ptsExpiry
	)

	status := int32(r)
	if status != SEC_E_OK {
		return nil, fmt.Errorf("Server AcquireCredentialsHandle failed with status 0x%08X", uint32(status))
	}

	ctx.hasCred = true
	return ctx, nil
}

// AcceptStep processes incoming client token and generates server challenge/response.
func (ctx *ServerSSPIContext) AcceptStep(clientTokenBase64 string) (serverToken string, done bool, err error) {
	if !ctx.hasCred {
		return "", false, fmt.Errorf("Server SSPI context is not initialized with credentials")
	}

	rawClientToken, err := base64.StdEncoding.DecodeString(clientTokenBase64)
	if err != nil {
		return "", false, fmt.Errorf("failed to decode client token base64: %w", err)
	}

	inSecBuffer := SecBuffer{
		cbBuffer:   uint32(len(rawClientToken)),
		BufferType: SECBUFFER_TOKEN,
		pvBuffer:   unsafe.Pointer(&rawClientToken[0]),
	}
	inDesc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  &inSecBuffer,
	}

	outSecBuffer := SecBuffer{
		cbBuffer:   0,
		BufferType: SECBUFFER_TOKEN,
		pvBuffer:   nil,
	}
	outDesc := SecBufferDesc{
		ulVersion: SECBUFFER_VERSION,
		cBuffers:  1,
		pBuffers:  &outSecBuffer,
	}

	var reqFlags uint32 = ASC_REQ_CONNECTION | ASC_REQ_ALLOCATE_MEMORY
	var contextAttr uint32
	var expiry TimeStamp

	var pInCtxt uintptr
	pOutCtxt := uintptr(unsafe.Pointer(&ctx.ctxtHandle))
	var pCred uintptr
	if ctx.hasCtxt {
		pCred = 0
		pInCtxt = uintptr(unsafe.Pointer(&ctx.ctxtHandle))
	} else {
		pCred = uintptr(unsafe.Pointer(&ctx.credHandle))
	}

	r, _, _ := procAcceptSecurityContext.Call(
		pCred,                                 // phCredential
		pInCtxt,                               // phContext
		uintptr(unsafe.Pointer(&inDesc)),      // pInput
		uintptr(reqFlags),                     // fContextReq
		SECURITY_NATIVE_DREP,                  // TargetDataRep
		pOutCtxt,                              // phNewContext
		uintptr(unsafe.Pointer(&outDesc)),     // pOutput
		uintptr(unsafe.Pointer(&contextAttr)), // pfContextAttr
		uintptr(unsafe.Pointer(&expiry)),      // ptsExpiry
	)

	status := int32(r)
	if ctx.ctxtHandle.dwLower != 0 || ctx.ctxtHandle.dwUpper != 0 {
		ctx.hasCtxt = true
	}

	if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
		procCompleteAuthToken.Call(
			uintptr(unsafe.Pointer(&ctx.ctxtHandle)),
			uintptr(unsafe.Pointer(&outDesc)),
		)
		if status == SEC_I_COMPLETE_NEEDED {
			status = SEC_E_OK
		} else {
			status = SEC_I_CONTINUE_NEEDED
		}
	}

	var rawOutToken []byte
	if outSecBuffer.cbBuffer > 0 && outSecBuffer.pvBuffer != nil {
		rawOutToken = make([]byte, outSecBuffer.cbBuffer)
		src := unsafe.Slice((*byte)(outSecBuffer.pvBuffer), outSecBuffer.cbBuffer)
		copy(rawOutToken, src)

		// Free SSPI-allocated buffer
		procFreeContextBuffer.Call(uintptr(outSecBuffer.pvBuffer))
	}

	if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
		return "", false, fmt.Errorf("AcceptSecurityContext failed with status 0x%08X", uint32(status))
	}

	if len(rawOutToken) > 0 {
		serverToken = base64.StdEncoding.EncodeToString(rawOutToken)
	}

	if status == SEC_E_OK {
		ctx.completed = true
		return serverToken, true, nil
	}

	return serverToken, false, nil
}

// Release releases all allocated server SSPI handles and resources.
func (ctx *ServerSSPIContext) Release() {
	if ctx == nil {
		return
	}
	if ctx.hasCtxt {
		procDeleteSecurityContext.Call(uintptr(unsafe.Pointer(&ctx.ctxtHandle)))
		ctx.hasCtxt = false
	}
	if ctx.hasCred {
		procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&ctx.credHandle)))
		ctx.hasCred = false
	}
}
