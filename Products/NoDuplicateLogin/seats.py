from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile

from zope.publisher.browser import BrowserPage
from DateTime import DateTime

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

    
    def __call__(self):
        # if request is post and has login, then set the login
        return self.render()
