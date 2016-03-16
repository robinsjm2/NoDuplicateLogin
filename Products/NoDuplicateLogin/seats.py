from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile

from zope.publisher.browser import BrowserPage
from DateTime import DateTime

from Products.CMFCore.utils import getToolByName

import traceback
import logging

logger = logging.getLogger('Products.NoDuplicateLogin')

class NoDuplicateLoginSeatsView(BrowserPage):

    index = ViewPageTemplateFile("seats.pt")

    def __init__(self, context, request):
        self.context = context
        self.request = request
        self.no_duplicate_login = context.unrestrictedTraverse("acl_users/no_duplicate_login")

    
    def render(self):
        return self.index()

    def saveSeatsForUser(self, login, seats_state):
        """ Saves the member properties defined in seats_state to the database. """
        mtool = getToolByName(self, 'portal_membership')
        member = mtool.getMemberById(login)
        # get the max_seats property from the member data tool
        if member is not None:
            member.setMemberProperties(mapping=seats_state)
    
    def updateSeatsCacheForLogin(self, login):
        """ Create or refresh the cached details for max_seats and other seats_state properties """
        # remove the current cache
        self.no_duplicate_login.clearSeatsPropertiesForLogin(login)

        cached_member_data = self.no_duplicate_login.getSeatsPropertiesForLogin(login)

        return cached_member_data

    def __call__(self):
        # if there is an action passed in, then carry out the action first
        action = self.request.get("action", None)
        login = self.request.get("login", "")
        max_seats = self.request.get("max-seats", 1)
        seats_timeout = self.request.get("seats-timeout", 5)

        if action == "clearAllTokens":
            try:
                self.no_duplicate_login.clearAllTokensForUser(login)
            except:
                traceback.print_exc()
        elif action == "clearStaleTokens":
            try:
                self.no_duplicate_login.clearStaleTokens(login)
            except:
                traceback.print_exc()
        elif action == "saveSeats":
            try:
                seats_state = {'max_seats': int( max_seats ), 'seat_timeout_in_minutes': float( seats_timeout )}
                self.saveSeatsForUser( login, seats_state )
                
                # Clear all tokens for user since the timeouts and max_seats changed.
                # If this is not done, then existing sessions could be kept alive even if more seats than the new max.
                # This is because they are only checked against max_seats when they are being activated (not while they are being kept active through continued use). 
                self.no_duplicate_login.clearAllTokensForUser(login)
            except:
                traceback.print_exc()

        # update the seats_state cache
        if len( login ) > 0:
            try:
                self.updateSeatsCacheForLogin(login)
            except:
                traceback.print_exc()

        # if request is post and has login, then set the login
        return self.render()
