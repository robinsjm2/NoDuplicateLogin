# Copyright (c) 2006, BlueDynamics, Klein & Partner KEG, Innsbruck,
# Austria, and the respective authors. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""NoDuplicateLogin plugin
"""

__author__ = "Jonathan Robinson <jrobinson@sanfordguide.com>"

from AccessControl import ClassSecurityInfo, Permissions
from BTrees.OOBTree import OOBTree
from DateTime import DateTime
from Globals import InitializeClass
from OFS.Cache import Cacheable
from Products.CMFCore.utils import getToolByName
from Products.CMFPlone import PloneMessageFactory as _
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins \
     import IAuthenticationPlugin, ICredentialsResetPlugin

from plone.session import tktauth
from plone.keyring.interfaces import IKeyManager
from urllib import quote, unquote
from utils import uuid
from zope.component import queryUtility
import datetime
import time
import traceback

manage_addNoDuplicateLoginForm = PageTemplateFile(
    'www/noduplicateloginAdd',
    globals(),
    __name__='manage_addNoDuplicateLoginForm')


def manage_addNoDuplicateLogin(dispatcher,
                               id,
                               title=None,
                               cookie_name='',
                               REQUEST=None):
    """Add a NoDuplicateLogin plugin to a Pluggable Auth Service."""

    obj = NoDuplicateLogin(id, title,
                           cookie_name=cookie_name)
    dispatcher._setObject(obj.getId(), obj)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect('%s/manage_workspace?manage_tabs_message='
                                     'NoDuplicateLogin+plugin+added.'
                                     % dispatcher.absolute_url())


class NoDuplicateLogin(BasePlugin, Cacheable):

    """PAS plugin that rejects multiple logins with the same user at
    the same time, by forcing a logout of all but one user.  If a user has max_seats > 1, then it will reject users after maximum seats are filled.
    """

    meta_type = 'No Duplicate Login Plugin'
    cookie_name = '__noduplicate'
    DEBUG = True
    security = ClassSecurityInfo()
    login_member_data_mapping = None

    _properties = (
        {'id': 'title', 'label': 'Title', 'type': 'string', 'mode': 'w'},
        {'id': 'cookie_name', 'label': 'Cookie Name', 'type': 'string',
            'mode': 'w'},
        )

    # UIDs older than 30 minutes are deleted from our storage...
    time_to_persist_cookies = datetime.timedelta(minutes=30)

    # XXX I wish I had a better explanation for this, but disabling this makes
    # both the ZMI (basic auth) work and the NoDuplicateLogin work.
    # Otherwise, we get a traceback on basic auth. I suspect that means this
    # plugin needs to handle basic auth better but I'm not sure how or why.
    # Normally, we would prefer to see our exceptions.
    _dont_swallow_my_exceptions = False

    def __init__(self, id, title=None, cookie_name=''):
        self._id = self.id = id
        self.title = title

        if cookie_name:
            self.cookie_name = cookie_name

        self.mapping1 = OOBTree()  # userid : { tokens:[ UID, UID, UID] }
        self.mapping2 = OOBTree()  # UID : { userid: string, startTime: DateTime, expireTime: DateTime }
        self.login_member_data_mapping = OOBTree()  # userid : { maxSeats: integer, expireTime: DateTime }

        self.plone_session = None  # for plone.session

    security.declarePrivate('authenticateCredentials')

    def authenticateCredentials(self, credentials):
        """See IAuthenticationPlugin.

        This plugin will actually never authenticate.

        o We expect the credentials to be those returned by
          ILoginPasswordExtractionPlugin.
        """
        request = self.REQUEST
        response = request['RESPONSE']
        pas_instance = self._getPAS()

        login = credentials.get('login')
        password = credentials.get('password')

        if None in (login, password, pas_instance) and (
            credentials.get('source') != 'plone.session'):
            return None
        else:
            session_source = self.session

            ticket = credentials.get('cookie')

            if session_source._shared_secret is not None:
                ticket_data = tktauth.validateTicket(
                    session_source._shared_secret, ticket,
                    timeout=session_source.timeout,
                    mod_auth_tkt=session_source.mod_auth_tkt)
            else:
                ticket_data = None
                manager = queryUtility(IKeyManager)
                if manager is None:
                    return None
                for secret in manager[u"_system"]:
                    if secret is None:
                        continue

                    ticket_data = tktauth.validateTicket(secret, ticket,
                        timeout=session_source.timeout,
                        mod_auth_tkt=session_source.mod_auth_tkt)

                    if ticket_data is not None:
                        break

            if ticket_data is None:
                return None

            (digest, userid, tokens, user_data, timestamp) = ticket_data
            pas = self._getPAS()
            info = pas._verifyUser(pas.plugins, user_id=userid)

            if info is None:
                return None

            login = info['login']

        cookie_val = self.getCookie()
        
        # initialize max_seats at 1
        max_seats = 1

        if self.login_member_data_mapping is None:
            self.login_member_data_mapping = OOBTree() # if this has not been initialized then do it now
            if self.DEBUG:
                print "Initialized the Login Member Data Mapping"
  
        # if the max_seats has a valid cached value, then use it
        cached_member_data = self.login_member_data_mapping.get(login, None)
        
        now = DateTime()
        if cached_member_data and 'expireTime' in cached_member_data and 'maxSeats' in cached_member_data and now < cached_member_data['expireTime']:
            max_seats = cached_member_data['maxSeats']
        else:
            mtool = getToolByName(self, 'portal_membership')
            member = mtool.getMemberById(login)
            # get the max_seats property from the member data tool
            if member is not None:
                max_seats = member.getProperty("max_seats")
                # cache the max_seats for login
                self.login_member_data_mapping[login] = { 'maxSeats': int( max_seats ), 'expireTime': DateTime( now.asdatetime() + self.time_to_persist_cookies )}
                
        # When debugging, print the maxSeats value that was resolved
        if self.DEBUG:
            print "authenticateCredentials():: Max Seats is " + str( max_seats )

        if max_seats == 1:
            if cookie_val:
                # A cookie value is there.  If it's the same as the value
                # in our mapping, it's fine.  Otherwise we'll force a
                # logout.
                existing = self.mapping1.get(login, None)
                
                if self.DEBUG:
                    if existing:
                        print "authenticateCredentials():: cookie_val is " + cookie_val + ", and active tokens are: " + ', '.join( existing['tokens'] )
                
                if existing and cookie_val not in existing['tokens']:
                    # The cookies values differ, we want to logout the
                    # user by calling resetCredentials.  Note that this
                    # will eventually call our own resetCredentials which
                    # will cleanup our own cookie.
                    try:
                        self.resetAllCredentials(request, response)
                        pas_instance.plone_utils.addPortalMessage(_(
                            u"Someone else logged in under your name.  You have been \
                            logged out"), "error")
                    except:
                        traceback.print_exc()
                elif existing is None:
                    # The browser has the cookie but we don't know about
                    # it.  Let's reset our own cookie:
                    self.setCookie('')
    
            else:
                # When no cookie is present, we generate one, store it and
                # set it in the response:
                cookie_val = uuid()
                # do some cleanup in our mappings
                existing = self.mapping1.get(login)
                if existing and 'tokens' in existing:
                    if existing['tokens'][0] in self.mapping2:
                        del self.mapping2[existing['tokens'][0]]
    
                now = DateTime()
                self.mapping1[login] = { 'tokens':[] };
                self.mapping1[login]['tokens'].append( cookie_val )
                self.mapping2[cookie_val] = {'userid': login, 'startTime': now, 'expireTime': DateTime( now.asdatetime() + self.time_to_persist_cookies )}
                self.setCookie(cookie_val)
        else:
            # Max seats is not 1. Treat this as a floating licenses scenario.
            # Nobody is logged out, but once the max seats threshold is reached,
            # active tokens must expire before new users may log in.
            if cookie_val:
                # A cookie value is there.  If it's the same as the value
                # in our mapping, it's fine.  Otherwise we'll force a
                # logout.
                existing = self.mapping1.get(login, None)
                
                if self.DEBUG:
                    if existing:
                        print "authenticateCredentials():: cookie_val is " + cookie_val + ", and active tokens are: " + ', '.join( existing['tokens'] )
                
                try:
                    # if the cookie is in the active tokens for the given login
                    if existing and cookie_val in existing['tokens']:
                        tokenInfo = self.mapping2.get( cookie_val, None )
                        now = DateTime()
                        extendedExpireTime = DateTime( now.asdatetime() + self.time_to_persist_cookies )
                        
                        # if the token in the cookie has not expired on the server-side, then extend its expireTime
                        if tokenInfo and 'expireTime' in tokenInfo and tokenInfo['expireTime'] > now:
                            self.mapping2[cookie_val]['expireTime'] = extendedExpireTime
                        else:
                            # since the cookie expired, set the startTime to now and the expireTime based on that
                            self.mapping2[cookie_val] = { 'userid': login, 'startTime': now, 'expireTime': extendedExpireTime }
                        
                    else:
                        # the token stored in the cookie is not in the list of tokens on the server-side. let's re-issue a token.
                        self.issueToken(login, max_seats, request, response)
                except:
                    traceback.print_exc()
    
            else:
                if self.DEBUG:
                    print "authenticateCredentials:: Try to issue a token because there is no cookie value."
                    
                # When no cookie is present, attempt to issue a token and use the cookie to store it
                self.issueToken(login, max_seats, request, response)
    
        return None  # Note that we never return anything useful

    security.declarePrivate('resetCredentials')

    def resetCredentials(self, request, response):
        """See ICredentialsResetPlugin.
        """
        if self.DEBUG:
            print "resetCredentials()::"
        try:
            cookie_val = self.getCookie()
            if cookie_val:
                loginandinfo = self.mapping2.get(cookie_val, None)
                if loginandinfo:
                    login = loginandinfo['userid']
                    del self.mapping2[cookie_val]
                    existing = self.mapping1.get(login, None)
                    if existing:
                        assert cookie_val not in existing['tokens']
    
            self.setCookie('')
        except:
            if self.DEBUG:
                traceback.print_exc()

    security.declarePrivate('resetAllCredentials')

    def resetAllCredentials(self, request, response):
        """Call resetCredentials of all plugins.

        o This is not part of any contract.
        """
        # This is arguably a bit hacky, but calling
        # pas_instance.resetCredentials() will not do anything because
        # the user is still anonymous.  (I think it should do
        # something nevertheless.)
        pas_instance = self._getPAS()
        plugins = pas_instance._getOb('plugins')
        cred_resetters = plugins.listPlugins(ICredentialsResetPlugin)
        for resetter_id, resetter in cred_resetters:
            resetter.resetCredentials(request, response)

    security.declarePrivate('getCookie')

    def getCookie(self):
        """Helper to retrieve the cookie value from either cookie or
        session, depending on policy.
        """
        request = self.REQUEST
        cookie = request.get(self.cookie_name, '')
        
        if self.DEBUG:
            print "getCookie():: " + str(unquote(cookie))
        
        return unquote(cookie)

    security.declarePrivate('setCookie')

    def setCookie(self, value):
        """Helper to set the cookie value to either cookie or
        session, depending on policy.

        o Setting to '' means delete.
        """
        value = quote(value)
        request = self.REQUEST
        response = request['RESPONSE']

        if value:
            response.setCookie(self.cookie_name, value, path='/')
        else:
            response.expireCookie(self.cookie_name, path='/')
            
        if self.DEBUG:
            print "setCookie():: " + str(value)
    
    security.declarePrivate('clearStaleTokens')
    def clearStaleTokens(self, login):
        
        if self.DEBUG:
            print "clearStaleTokens:: " + login

        existing = self.mapping1.get(login, None)
        
        if existing and 'tokens' in existing:
            # for each token, remove if stale
            for token in existing['tokens']:
                tokenInfo = self.mapping2.get( token, None )
                
                now = DateTime()
                # if the expireTime for the token has passed, then expire the token
                if tokenInfo and 'expireTime' in tokenInfo and tokenInfo['expireTime'] < now:
                    if self.DEBUG:
                        print "clearStaleTokens:: Remove token (%s) because expireTime(%s). startTime(%s)" % (token, tokenInfo['expireTime'], tokenInfo['startTime'] )
                    # remove from the active tokens for the given login
                    self.mapping1[login]['tokens'].remove(token)
                    del self.mapping2[token]

    security.declarePrivate('issueToken')
    def issueToken(self, login, max_seats, request, response):
        # When no cookie is present, we generate one, store it and
        # set it in the response:
        cookie_val = uuid()
        iTokens = 0 # assume no tokens are active until proven otherwise
        existing = self.mapping1.get(login)
        if existing and 'tokens' in existing:
            iTokens = len( existing['tokens'] )
        else:
            self.mapping1[login] = { 'tokens':[] } # initialize tokens array for this login
        
        if self.DEBUG:
            print "issueToken:: login = %s, active = %i, max = %i" % (login, iTokens, max_seats)

        if iTokens < max_seats:
            self.setCookie(cookie_val)
            
            now = DateTime()
            self.mapping1[login]['tokens'].append( cookie_val )
            self.mapping2[cookie_val] = {'userid': login, 'startTime': now, 'expireTime': DateTime( now.asdatetime() + self.time_to_persist_cookies )}
            
            if self.DEBUG:
                print "issueToken:: after issue token, active tokens = " + ', '.join(self.mapping1[login]['tokens'])
            
            # if this is the last token to issue,
            # then go ahead and clear stale tokens for this login
            if iTokens + 1 == max_seats:
                self.clearStaleTokens(login)
        else:
            # cannot issue cookie, so clear in browser-side
            self.setCookie('')

            # if the token is not able to be issued because of max_seats filled,
            # then clear stale tokens, and show the message
            self.clearStaleTokens(login)

            # Logout the
            # user by calling resetCredentials.  Note that this
            # will eventually call our own resetCredentials which
            # will cleanup our own cookie.
            try:
                self.resetAllCredentials(request, response)
                self._getPAS().plone_utils.addPortalMessage(_(
                    u"The maximum number of simultaneous logins for this user has been exceeded.  You have been \
                    logged out."), "error")
            except:
                traceback.print_exc()
    
    security.declareProtected(Permissions.manage_users, 'clearAllTokens')
    def clearAllTokens(self):
        """Clear all server side tokens.  Use only in testing."""
        if self.DEBUG:
            print "clearAllTokens():: called"

        try:
            self.mapping1.clear()
            self.mapping2.clear()
        except:
            traceback.print_exc()

    security.declareProtected(Permissions.manage_users, 'cleanUp')

    def cleanUp(self):
        """Clean up storage.

        Call this periodically through the web to clean up old entries
        in the storage."""
        now = DateTime()

        def cleanStorage(mapping):
            count = 0
            for key, obj in mapping.items():
                # if this is not a dictionary, then it is a stale entry (could be tuple from old scheme)
                if not isinstance( obj, dict ):
                    del mapping[key]
                    count += 1
                elif 'expireTime' in obj and obj['expireTime'] < now:
                    del mapping[key]
                    
                    # if the mapping2 deletes its token by UID, make sure that the mapping1 removes that token as well
                    for userid, info in self.mapping1.items():
                        try:
                            info['tokens'].remove(key) # remove the UID from the tokens for that login
                        except:
                            pass
                    count += 1
            return count

        for mapping in self.mapping2, self.login_member_data_mapping:
            count = cleanStorage(mapping)

        return "%s entries deleted." % count

classImplements(NoDuplicateLogin,
                IAuthenticationPlugin,
                ICredentialsResetPlugin)

InitializeClass(NoDuplicateLogin)
