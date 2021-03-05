package com.horizon.exchangeapi.auth

import akka.http.scaladsl.model.StatusCode
import akka.http.scaladsl.model.headers.Language
import com.horizon.exchangeapi.{ApiRespType, ApiResponse, ExchMsg, HttpCode}

import javax.security.auth.login.LoginException

// Base class for all of the exchange authentication and authorization failures
// See also case class AuthRejection in ApiUtils.scala that can turn any exception into a rejection
//todo: make all of these final case classes
class AuthException(var httpCode: StatusCode, var apiResponse: String, msg: String) extends LoginException(msg) {
  def toComplete = (httpCode, ApiResponse(apiResponse, getMessage))
}

// These error msgs are matched by UsersSuite.scala, so change them there if you change them here
final case class OrgNotFound(authInfoOrg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("org.not.found.user.facing.error", authInfoOrg))
final case class IncorrectOrgFound(authInfoOrg: String, userInfoAcctId: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("incorrect.org.found.user.facing.error", authInfoOrg, userInfoAcctId))
final case class IncorrectOrgFoundMult(authInfoOrg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("incorrect.org.found.user.facing.error.mult", authInfoOrg))
final case class IncorrectIcpOrgFound(requestOrg: String, clusterName: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("incorrect.org.found.user.facing.error.ICP", requestOrg, clusterName))

// Error class to use to define specific error responses from problems happening in DB threads
// Note: this is not strictly an auth error, but it is handy to inherit from AuthException
class DBProcessingError(httpCode: StatusCode, apiResponse: String, msg: String) extends AuthException(httpCode, apiResponse, msg)

// These 2 exceptions will be caught by IbmCloudModule and Module respectively, and return false from login().
// Their http code should never be used, which is why it is an internal error if it unexpectedly is.
// Only used internally: The creds werent ibm cloud creds, so return gracefully and move on to the next login module
class NotIbmCredsException(implicit acceptLang: Language) extends AuthException(HttpCode.INTERNAL_ERROR, ApiRespType.INTERNAL_ERROR, "not IBM cloud credentials")
// The creds werent local exchange creds, so return gracefully and move on to the next login module
class NotLocalCredsException(implicit acceptLang: Language) extends AuthException(HttpCode.INTERNAL_ERROR, ApiRespType.INTERNAL_ERROR, "User is iamapikey or iamtoken, so credentials are not local Exchange credentials")

// We are in the middle of a db migration, so cant authenticate/authorize anything else
class IsDbMigrationException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.ACCESS_DENIED, ApiRespType.ACCESS_DENIED, ExchMsg.translate("in.process.db.migration"))

// Exceptions for handling DB connection errors
class DbTimeoutException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.GW_TIMEOUT, ApiRespType.GW_TIMEOUT, msg)
class DbConnectionException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BAD_GW, ApiRespType.BAD_GW, msg)

class InvalidCredentialsException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("invalid.credentials"))

class OrgNotSpecifiedException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("org.not.specified"))

class AccessDeniedException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.ACCESS_DENIED, ApiRespType.ACCESS_DENIED, ExchMsg.translate("access.denied"))

class BadInputException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BAD_INPUT, ApiRespType.BAD_INPUT, ExchMsg.translate("bad.input"))

class ResourceNotFoundException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.NOT_FOUND, ApiRespType.NOT_FOUND, ExchMsg.translate("not.found"))

class UserCreateException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BAD_GW, ApiRespType.BAD_GW, ExchMsg.translate("error.creating.user.noargs"))

// Not currently used. The IAM token we were given was expired, or some similar problem
//class BadIamCombinationException(msg: String) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, msg)

// Unexpected http code or response body from an IAM API call
class IamApiErrorException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BAD_GW, ApiRespType.BAD_GW, msg)

// Didn't get a response from an IAM API after a number of retries
class IamApiTimeoutException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.GW_TIMEOUT, ApiRespType.GW_TIMEOUT, msg)

// An error occurred while building the SSLSocketFactory with the self-signed cert
class SelfSignedCertException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.INTERNAL_ERROR, ApiRespType.INTERNAL_ERROR, msg)

// The creds id was not found in the db
class IdNotFoundException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.BADCREDS, ApiRespType.BADCREDS, ExchMsg.translate("invalid.credentials"))

// The id was not found in the db when looking for owner or isPublic
class IdNotFoundForAuthorizationException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.ACCESS_DENIED, ApiRespType.ACCESS_DENIED, ExchMsg.translate("access.denied"))

class AuthInternalErrorException(msg: String)(implicit acceptLang: Language) extends AuthException(HttpCode.INTERNAL_ERROR, ApiRespType.INTERNAL_ERROR, msg)
