#include "EdhocCredentialManager.h"

#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>

#include "RunningContext.h"
#include "Utils.h"

static constexpr const char* kFormat = "format";
static constexpr const char* kPrivateKeyId = "privateKeyID";
static constexpr const char* kPublicKey = "publicKey";
static constexpr const char* kKid = "kid";
static constexpr const char* kIsCBOR = "isCBOR";
static constexpr const char* kCredentials = "credentials";
static constexpr const char* kX5chain = "x5chain";
static constexpr const char* kCertificate = "certificate";
static constexpr const char* kCertificates = "certificates";
static constexpr const char* kX5t = "x5t";
static constexpr const char* kHash = "hash";
static constexpr const char* kHashAlgorithm = "hashAlgorithm";
static constexpr const char* kUnsupportedCredentialTypeError = "Unsupported credential type specified";
static constexpr const char* kInvalidInputCredentialTypeError = "Invalid credentials object specified";
static constexpr const char* kInvalidInputDataErrorKid = "Invalid input data for Key ID";
static constexpr const char* kInvalidInputDataErrorX509Chain = "Invalid input data for X.509 chain";
static constexpr const char* kInvalidInputDataErrorX509Hash = "Invalid input data for X.509 hash";
static constexpr const char* kErrorObjectExpected = "Object expected";

static Napi::Value copy_if_buffer(Napi::Env env, const Napi::Value& value) {
  if (value.IsBuffer()) {
    auto buf = value.As<Napi::Buffer<uint8_t>>();
    return Napi::Buffer<uint8_t>::Copy(env, buf.Data(), buf.Length());
  }
  return value;
}

static Napi::Object clone_credentials_object(Napi::Env env, const Napi::Object& credsObj) {
  if (!credsObj.Has(kFormat)) {
    throw std::runtime_error(kInvalidInputCredentialTypeError);
  }

  Napi::Object out = Napi::Object::New(env);
  out.Set(kFormat, credsObj.Get(kFormat));

  // Optional fields that can appear on credentials object
  if (credsObj.Has(kPrivateKeyId) && !credsObj.Get(kPrivateKeyId).IsNull() && !credsObj.Get(kPrivateKeyId).IsUndefined()) {
    out.Set(kPrivateKeyId, copy_if_buffer(env, credsObj.Get(kPrivateKeyId)));
  }
  if (credsObj.Has(kPublicKey) && !credsObj.Get(kPublicKey).IsNull() && !credsObj.Get(kPublicKey).IsUndefined()) {
    out.Set(kPublicKey, copy_if_buffer(env, credsObj.Get(kPublicKey)));
  }

  const int label = credsObj.Get(kFormat).As<Napi::Number>().Int32Value();
  switch (label) {
    case EDHOC_COSE_HEADER_KID: {
      Napi::Object kidObj = credsObj.Get(kKid).As<Napi::Object>();
      Napi::Object newKidObj = Napi::Object::New(env);

      if (kidObj.Has(kIsCBOR)) {
        newKidObj.Set(kIsCBOR, kidObj.Get(kIsCBOR));
      }
      if (kidObj.Has(kKid)) {
        newKidObj.Set(kKid, copy_if_buffer(env, kidObj.Get(kKid)));
      }
      if (kidObj.Has(kCredentials)) {
        newKidObj.Set(kCredentials, copy_if_buffer(env, kidObj.Get(kCredentials)));
      }

      out.Set(kKid, newKidObj);
      break;
    }
    case EDHOC_COSE_HEADER_X509_CHAIN: {
      Napi::Object x5chainObj = credsObj.Get(kX5chain).As<Napi::Object>();
      Napi::Object newX5chainObj = Napi::Object::New(env);

      if (x5chainObj.Has(kCertificates)) {
        Napi::Array certArray = x5chainObj.Get(kCertificates).As<Napi::Array>();
        Napi::Array newCertArray = Napi::Array::New(env, certArray.Length());
        for (uint32_t i = 0; i < certArray.Length(); ++i) {
          newCertArray.Set(i, copy_if_buffer(env, certArray.Get(i)));
        }
        newX5chainObj.Set(kCertificates, newCertArray);
      }

      out.Set(kX5chain, newX5chainObj);
      break;
    }
    case EDHOC_COSE_HEADER_X509_HASH: {
      Napi::Object x5tObj = credsObj.Get(kX5t).As<Napi::Object>();
      Napi::Object newX5tObj = Napi::Object::New(env);

      if (x5tObj.Has(kCertificate) && !x5tObj.Get(kCertificate).IsUndefined() && !x5tObj.Get(kCertificate).IsNull()) {
        newX5tObj.Set(kCertificate, copy_if_buffer(env, x5tObj.Get(kCertificate)));
      }
      if (x5tObj.Has(kHash)) {
        newX5tObj.Set(kHash, copy_if_buffer(env, x5tObj.Get(kHash)));
      }
      if (x5tObj.Has(kHashAlgorithm)) {
        newX5tObj.Set(kHashAlgorithm, x5tObj.Get(kHashAlgorithm));
      }

      out.Set(kX5t, newX5tObj);
      break;
    }
    default:
      throw std::runtime_error(kUnsupportedCredentialTypeError);
  }

  return out;
}

/*
 * Convert a JavaScript object to an edhoc_auth_cred_key_id
 */
void convert_js_to_edhoc_kid(const Napi::Object& jsObject, struct edhoc_auth_creds* credentials) {
  Napi::Object kidObj = jsObject.Get(kKid).As<Napi::Object>();
  if (!kidObj.Has(kIsCBOR) || !kidObj.Has(kKid) || !kidObj.Has(kCredentials)) {
    throw std::runtime_error(kInvalidInputDataErrorKid);
  }

  credentials->label = EDHOC_COSE_HEADER_KID;

  if (kidObj.Get(kKid).IsNumber()) {
    int64_t numeric = kidObj.Get(kKid).As<Napi::Number>().Int64Value();
    if (numeric >= ONE_BYTE_CBOR_INT_MIN_VALUE && numeric <= ONE_BYTE_CBOR_INT_MAX_VALUE) {
      credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
      credentials->key_id.key_id_int = (int32_t)numeric;
    } else {
      size_t length = 0;
      Utils::EncodeInt64ToBuffer(numeric, credentials->key_id.key_id_bstr, &length);
      credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
      credentials->key_id.key_id_bstr_length = length;
    }
  } else if (kidObj.Get(kKid).IsBuffer()) {
    Napi::Buffer<uint8_t> buffer = kidObj.Get(kKid).As<Napi::Buffer<uint8_t>>();
    credentials->key_id.encode_type = EDHOC_ENCODE_TYPE_BYTE_STRING;
    credentials->key_id.key_id_bstr_length = buffer.Length();
    memcpy(credentials->key_id.key_id_bstr, buffer.Data(), buffer.Length());
  } else {
    throw std::runtime_error(kInvalidInputDataErrorKid);
  }

  Napi::Buffer<uint8_t> credBuffer = kidObj.Get(kCredentials).As<Napi::Buffer<uint8_t>>();
  credentials->key_id.cred = credBuffer.Data();
  credentials->key_id.cred_len = credBuffer.Length();
  credentials->key_id.cred_is_cbor = kidObj.Get(kIsCBOR).As<Napi::Boolean>().Value();
}

/*
 * Convert a JavaScript object to an edhoc_auth_cred_x509_chain
 */
void convert_js_to_edhoc_x5chain(const Napi::Object& jsObject, struct edhoc_auth_creds* credentials) {
  Napi::Object x5chainObj = jsObject.Get(kX5chain).As<Napi::Object>();
  if (!x5chainObj.Has(kCertificates)) {
    throw std::runtime_error(kInvalidInputDataErrorX509Chain);
  }

  credentials->label = EDHOC_COSE_HEADER_X509_CHAIN;

  Napi::Array certArray = x5chainObj.Get(kCertificates).As<Napi::Array>();
  size_t nr_of_certs = certArray.Length();
  credentials->x509_chain.nr_of_certs = nr_of_certs;

  for (size_t i = 0; i < nr_of_certs; ++i) {
    Napi::Buffer<uint8_t> certBuffer = certArray.Get(i).As<Napi::Buffer<uint8_t>>();
    credentials->x509_chain.cert[i] = certBuffer.Data();
    credentials->x509_chain.cert_len[i] = certBuffer.Length();
  }
}

/*
 * Convert a JavaScript object to an edhoc_auth_cred_x509_hash
 */
void convert_js_to_edhoc_x5t(const Napi::Object& jsObject, struct edhoc_auth_creds* credentials) {
  Napi::Object x5tObj = jsObject.Get(kX5t).As<Napi::Object>();
  if (!x5tObj.Has(kCertificate) || !x5tObj.Has(kHash) || !x5tObj.Has(kHashAlgorithm)) {
    throw std::runtime_error(kInvalidInputDataErrorX509Hash);
  }

  credentials->label = EDHOC_COSE_HEADER_X509_HASH;

  Napi::Buffer<uint8_t> certBuffer = x5tObj.Get(kCertificate).As<Napi::Buffer<uint8_t>>();
  credentials->x509_hash.cert = certBuffer.Data();
  credentials->x509_hash.cert_len = certBuffer.Length();

  Napi::Buffer<uint8_t> hashBuffer = x5tObj.Get(kHash).As<Napi::Buffer<uint8_t>>();
  credentials->x509_hash.cert_fp = hashBuffer.Data();
  credentials->x509_hash.cert_fp_len = hashBuffer.Length();

  credentials->x509_hash.encode_type = EDHOC_ENCODE_TYPE_INTEGER;
  credentials->x509_hash.alg_int = x5tObj.Get(kHashAlgorithm).As<Napi::Number>().Int32Value();
}

/*
 * Convert an edhoc_auth_cred_key_id to a JavaScript object
 */
Napi::Object convert_edhoc_kid_to_js(const Napi::Env& env, const struct edhoc_auth_cred_key_id& kid) {
  Napi::Object obj = Napi::Object::New(env);
  obj.Set(kIsCBOR, Napi::Boolean::New(env, kid.cred_is_cbor));

  if (kid.encode_type == EDHOC_ENCODE_TYPE_INTEGER) {
    obj.Set(kKid, Napi::Number::New(env, kid.key_id_int));
  } else {
    obj.Set(kKid, Napi::Buffer<uint8_t>::Copy(env, kid.key_id_bstr, kid.key_id_bstr_length));
  }

  obj.Set(kCredentials, Napi::Buffer<uint8_t>::Copy(env, kid.cred, kid.cred_len));
  return obj;
}

/*
 * Convert an edhoc_auth_cred_x509_chain to a JavaScript object
 */
Napi::Object convert_edhoc_x5chain_to_js(const Napi::Env& env, const struct edhoc_auth_cred_x509_chain& x509_chain) {
  Napi::Object obj = Napi::Object::New(env);
  Napi::Array certArray = Napi::Array::New(env, x509_chain.nr_of_certs);

  for (size_t i = 0; i < x509_chain.nr_of_certs; ++i) {
    certArray.Set(i, Napi::Buffer<uint8_t>::Copy(env, x509_chain.cert[i], x509_chain.cert_len[i]));
  }

  obj.Set(kCertificates, certArray);
  return obj;
}

/*
 * Convert an edhoc_auth_cred_x509_hash to a JavaScript object
 */
Napi::Object convert_edhoc_x5t_to_js(const Napi::Env& env, const struct edhoc_auth_cred_x509_hash& x509_hash) {
  Napi::Object obj = Napi::Object::New(env);
  obj.Set(kCertificate, Napi::Buffer<uint8_t>::Copy(env, x509_hash.cert, x509_hash.cert_len));
  obj.Set(kHash, Napi::Buffer<uint8_t>::Copy(env, x509_hash.cert_fp, x509_hash.cert_fp_len));
  obj.Set(kHashAlgorithm, Napi::Number::New(env, x509_hash.alg_int));
  return obj;
}

/*
 * EdhocCredentialManager constructor
 */
EdhocCredentialManager::EdhocCredentialManager(Napi::Object& jsCredentialManager, Napi::Object& jsEdhoc) {
  if (!jsCredentialManager.IsObject() || !jsEdhoc.IsObject()) {
    Napi::Error::New(jsCredentialManager.Env(), kErrorObjectExpected).ThrowAsJavaScriptException();
  }
  credentialManagerRef_ = Napi::Persistent(jsCredentialManager);
  edhocRef_ = Napi::Weak(jsEdhoc);

  credentials.fetch = FetchCredentials;
  credentials.verify = VerifyCredentials;
}

/*
 * EdhocCredentialManager destructor
 */
EdhocCredentialManager::~EdhocCredentialManager() {
  credentialManagerRef_.Reset();
  edhocRef_.Reset();
  cachedPeerCredentialsRef_.Reset();
  for (auto& ref : credentialReferences_) {
    ref.Reset();
  }
  credentialReferences_.clear();
}

void EdhocCredentialManager::ClearCachedCredentials() {
  cachedPeerCredentialsRef_.Reset();
  for (auto& ref : credentialReferences_) {
    ref.Reset();
  }
  credentialReferences_.clear();
}

Napi::Value EdhocCredentialManager::GetCachedPeerCredentials(Napi::Env env) {
  if (cachedPeerCredentialsRef_.IsEmpty()) {
    return env.Null();
  }
  return cachedPeerCredentialsRef_.Value();
}

/*
 * Static method to fetch credentials
 */
int EdhocCredentialManager::FetchCredentials(void* user_context, struct edhoc_auth_creds* credentials) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  EdhocCredentialManager* manager = context->GetCredentialManager();
  return manager->callFetchCredentials(context, credentials);
}

/*
 * Static method to verify credentials
 */
int EdhocCredentialManager::VerifyCredentials(void* user_context,
                                              struct edhoc_auth_creds* credentials,
                                              const uint8_t** public_key_reference,
                                              size_t* public_key_length) {
  RunningContext* context = static_cast<RunningContext*>(const_cast<void*>(user_context));
  EdhocCredentialManager* manager = context->GetCredentialManager();
  return manager->callVerifyCredentials(context, credentials, public_key_reference, public_key_length);
}

/*
 * Method to fetch credentials
 */
int EdhocCredentialManager::callFetchCredentials(RunningContext* runningContext, struct edhoc_auth_creds* credentials) {

  auto successHandler = [this, &credentials](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    auto credsObj = result.As<Napi::Object>();

    if (credsObj.IsObject() == false || credsObj.Has(kFormat) == false) {
      throw std::runtime_error(kInvalidInputCredentialTypeError);
    }

    credentialReferences_.push_back(Napi::Persistent(credsObj));

    int label = credsObj.Get(kFormat).As<Napi::Number>().Int32Value();

    switch (label) {
      case EDHOC_COSE_HEADER_KID:
        convert_js_to_edhoc_kid(credsObj, credentials);
        break;
      case EDHOC_COSE_HEADER_X509_CHAIN:
        convert_js_to_edhoc_x5chain(credsObj, credentials);
        break;
      case EDHOC_COSE_HEADER_X509_HASH:
        convert_js_to_edhoc_x5t(credsObj, credentials);
        break;
      case EDHOC_COSE_ANY:
      default:
        throw Napi::Error::New(env, kUnsupportedCredentialTypeError);
    }

    if (credsObj.Has(kPrivateKeyId) && !credsObj.Get(kPrivateKeyId).IsNull()) {
      Napi::Buffer<uint8_t> privKeyIdBuffer = credsObj.Get(kPrivateKeyId).As<Napi::Buffer<uint8_t>>();
      memcpy(credentials->priv_key_id, privKeyIdBuffer.Data(), privKeyIdBuffer.Length());
    }

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this](Napi::Env env) {
    return std::vector<napi_value> { this->edhocRef_.Value() };
  };

  return runningContext->ThreadSafeBlockingCall(credentialManagerRef_, "fetch", argumentsHandler, successHandler);
}

/*
 * Method to verify credentials
 */
int EdhocCredentialManager::callVerifyCredentials(RunningContext* runningContext,
                                                  struct edhoc_auth_creds* credentials,
                                                  const uint8_t** public_key_reference,
                                                  size_t* public_key_length) {

  auto successHandler = [this, &credentials, &public_key_reference, &public_key_length](Napi::Env env, Napi::Value result) {
    Napi::HandleScope scope(env);
    Napi::Object credsObj = result.As<Napi::Object>();
    credentialReferences_.push_back(Napi::Persistent(credsObj));
    // Cache a deep copy of the final peer credentials object for later export.
    // (Deep copy prevents user-side mutations from affecting the cached value.)
    cachedPeerCredentialsRef_.Reset();
    cachedPeerCredentialsRef_ = Napi::Persistent(clone_credentials_object(env, credsObj));

    if (credsObj.IsObject() == false) {
      throw std::runtime_error(kInvalidInputCredentialTypeError);
    }

    int label = credsObj.Get(kFormat).As<Napi::Number>().Int32Value();
    switch (label) {
      case EDHOC_COSE_HEADER_KID:
        convert_js_to_edhoc_kid(credsObj, credentials);
        break;
      case EDHOC_COSE_HEADER_X509_CHAIN:
        convert_js_to_edhoc_x5chain(credsObj, credentials);
        break;
      case EDHOC_COSE_HEADER_X509_HASH:
        convert_js_to_edhoc_x5t(credsObj, credentials);
        break;
      default:
        throw std::runtime_error(kUnsupportedCredentialTypeError);
    }

    if (credsObj.Has(kPublicKey) && !credsObj.Get(kPublicKey).IsNull()) {
      Napi::Buffer<uint8_t> publicKeyBuffer = credsObj.Get(kPublicKey).As<Napi::Buffer<uint8_t>>();
      *public_key_reference = publicKeyBuffer.Data();
      *public_key_length = publicKeyBuffer.Length();
    }

    return EDHOC_SUCCESS;
  };

  auto argumentsHandler = [this, &credentials](Napi::Env env) {
    Napi::Object resultObject = Napi::Object::New(env);
    resultObject.Set(kFormat, Napi::Number::New(env, credentials->label));

    switch (credentials->label) {
      case EDHOC_COSE_HEADER_KID:
        resultObject.Set(kKid, convert_edhoc_kid_to_js(env, credentials->key_id));
        break;
      case EDHOC_COSE_HEADER_X509_CHAIN:
        resultObject.Set(kX5chain, convert_edhoc_x5chain_to_js(env, credentials->x509_chain));
        break;
      case EDHOC_COSE_HEADER_X509_HASH:
        resultObject.Set(kX5t, convert_edhoc_x5t_to_js(env, credentials->x509_hash));
        break;
      default:
        throw std::runtime_error(kUnsupportedCredentialTypeError);
    }
    return std::vector<napi_value> { 
      this->edhocRef_.Value(), 
      resultObject
    };
  };

  return runningContext->ThreadSafeBlockingCall(credentialManagerRef_, "verify", argumentsHandler, successHandler);
}
