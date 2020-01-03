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

"""NoDuplicateLogin
"""

__author__ = "Daniel Nouri <daniel.nouri@gmail.com>"

from AccessControl.Permissions import add_user_folders
from Products.PluggableAuthService import registerMultiPlugin
from plugin import NoDuplicateLogin, \
                   manage_addNoDuplicateLogin, \
                   manage_addNoDuplicateLoginForm

def initialize(context):
    """Initialize the NoDuplicateLogin plugin."""
    registerMultiPlugin(NoDuplicateLogin.meta_type)
    
    context.registerClass(NoDuplicateLogin,
                          permission=add_user_folders,
                          constructors=(manage_addNoDuplicateLoginForm,
                                        manage_addNoDuplicateLogin),
                          #icon='www/noduplicatelogin.png',
                          visibility=None,
                          )
