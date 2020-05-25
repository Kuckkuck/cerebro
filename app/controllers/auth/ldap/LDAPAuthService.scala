package controllers.auth.ldap

import java.util.Hashtable

import com.google.inject.Inject
import com.sun.jndi.ldap.LdapCtxFactory
import controllers.auth.AuthService
import javax.naming._
import javax.naming.directory.SearchControls
import play.api.{Configuration, Logger}

import scala.util.control.NonFatal

class LDAPAuthService @Inject()(globalConfig: Configuration) extends AuthService {

  private val log = Logger(this.getClass)

  private final val config = new LDAPAuthConfig(globalConfig.get[Configuration]("auth.settings"))

  def checkUserAuth(username: String, password: String): Boolean = {
    val props = new Hashtable[String, String]()
    log.info(s"checkUserAuth")
    props.put(Context.SECURITY_PRINCIPAL, config.userTemplate.format(username, config.baseDN))
    props.put(Context.SECURITY_CREDENTIALS, password)

    try {
      log.info(s"try checkUserAuth")
      LdapCtxFactory.getLdapCtxInstance(config.url, props)
      true
    } catch {
      case e: AuthenticationException =>
        log.info(s"login of $username failed with: ${e.getMessage}")
        false
      case NonFatal(e) =>
        log.error(s"login of $username failed", e)
        false
    }
  }

  def checkGroupMembership(username: String, groupConfig: LDAPGroupSearchConfig): Boolean = {
    val props = new Hashtable[String, String]()
    props.put(Context.SECURITY_PRINCIPAL, config.bindDN)
    props.put(Context.SECURITY_CREDENTIALS, config.bindPwd)
    props.put(Context.REFERRAL, "follow")
    val user     = groupConfig.userAttrTemplate.format(username, config.baseDN)
    val controls = new SearchControls()
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
    try {
      log.info(s"try checkGroupMembership")
      val context = LdapCtxFactory.getLdapCtxInstance(config.url, props)
      val search = context.search(groupConfig.baseDN,s"(& (${groupConfig.userAttr}=$user)(${groupConfig.group}))", controls)
      context.close()
      log.info(s"checkGroupMembership: $search") 
      search.hasMore()
    } catch {
      case e: AuthenticationException =>
        log.info(s"User $username doesn't fulfill condition (${groupConfig.group}) : ${e.getMessage}")
        false
      case NonFatal(e) =>
        log.error(s"Unexpected error while checking group membership of $username", e)
        false
    }
  }

  def auth(username: String, password: String): Option[String] = {
    log.info(s"auth")
    log.info(s"checkGoupMembership LDAPGroupSearchConfig: $LDAPGroupSearchConfig")
    val isValidUser = config.groupMembership match {
      case Some(groupConfig) => checkGroupMembership(username, groupConfig) && checkUserAuth(username, password)
      case None              => checkUserAuth(username, password)
    }
    log.info(s"auth: $isValidUser")
    if (isValidUser) Some(username) else None
  }

}
