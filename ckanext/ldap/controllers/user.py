import re
import uuid
import logging
import ldap, ldap.filter
import ckan.plugins as p
import ckan.model
import pylons

from ckan.lib.helpers import flash_notice, flash_error
from ckan.common import _, request
from ckan.model.user import User
from ckanext.ldap.plugin import config
from ckanext.ldap.model.ldap_user import LdapUser
from pylons import config

import ckan.logic as logic
ValidationError = logic.ValidationError
#Anja, 5.9.18 for password reset
check_access = logic.check_access
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
UsernamePasswordError = logic.UsernamePasswordError

from ckan.common import _, c, g, request, response
import ckan.lib.mailer as mailer
import ckan.lib.base as base
render = base.render
abort = base.abort
#Anja, 5.9.18 for password reset END

#Anja, 5.9.18 - move register and lgin from ccca plugin to ldapPublicKey
import ckan.model as model
import ckan.logic.schema as schema
import ckan.authz as authz
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.lib.captcha as captcha
import os
DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten
_validate = dictization_functions.validate
import hashlib
import ldif
import ckan.lib.helpers as h
import paste.deploy.converters

#Anja - 26.9.2018
import ldap.modlist
from ckanext.ldap.lib.helpers import check_mail_org

#Anja, 5.9.18 - move register and login from ccca plugin to ldapPublicKey END

log = logging.getLogger(__name__)


class MultipleMatchError(Exception):
    pass
class UserConflictError(Exception):
    pass


class UserController(p.toolkit.BaseController):

    new_user_form = 'user/new_user_form.html'
    new_user_reply = 'user/new_user_reply.html'

    def delete(self, id):
        '''
        Delete user with id passed as parameter

        Delete first all LDAP entries and last delete
        and purge CKAN user. Thus the delete method is
        still available even if some Ldap deletes failed
        i.e. because of server down or similar
        '''

        context = {'model': model,
                   'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj}
        data_dict = {'id': id, 'include_datasets':True} #Check if user has public datasets

        # Store whether there were errors
        some_errors = False

        # Get User dict
        try:
            user_dict = p.toolkit.get_action('user_show')(context, data_dict)

            user_obj = context['user_obj']

        except NotFound, e:
            msg = _('User not found. "{user_id}". Please contact datenzentrum@ccca.ac.at.')
            abort(403, msg.format(user_id=id))

        # Get LDAP User dict
        try:
            ldap_user_dict = _find_ldap_user(user_dict['name'])
        except NotFound, e:
            some_errors = True
            log.error('LDAP User not found.')
            h.flash_error(_('LDAP User not found. Please check the log files'))

        if not ldap_user_dict:
            some_errors = True
            h.flash_error( _('The LDAP User not found. Please check the log files.'))

        # Delete LDAP Entries
        try:
            if ldap_user_dict and _delete_ldap_user(ldap_user_dict):
                user_index = h.url_for(controller='user', action='index')
            else:
                msg = _('Unable to delete the LDAP User with name "{user_id}". Please check log files for further details.')
                h.flash_error( msg.format(user_id=user_dict['name']))

        except:
            some_errors = True
            msg = _('Unable to delete LDAP User with name "{user_id}".  Please check the log files.')
            h.flash_error( msg.format(user_id=user_dict['name']))

        # Remove LdapUser entry = Database entry with match ckan_id - ldap_id
        try:
            ldap_user = LdapUser.by_user_id(user_dict['id'])

            if ldap_user:
                ckan.model.Session.delete(ldap_user)
                ckan.model.Session.commit()
        except:
            some_errors = True
            h.flash_error(_(' Unable to remove ldap table entry.  Please check the log files.'))

        #Check if the user has datasets
        if len(user_dict['datasets']) > 0:
            for x in user_dict['datasets']:
                if not x['private']:
                    msg = _('User "{user_id}" has public datasets: "{pkg_id}".')
                    h.flash_notice(msg.format(user_id=user_dict['name']), pkg_id=x['name'])
                else:
                    try:
                        p.toolkit.get_action('dataset_purge')(context, {'id':x['name']})
                    except:
                        some_errors = True
                        log.error ("Error purging: " +  x['name'])
                        msg = _('Error deleting "{pkg_id}": "{error_message}"')
                        h.flash_error( msg.format(pkg_id=x['name'], error_message=e))


        # Delete CKAN USER
        try:
            p.toolkit.get_action('user_delete')(context, data_dict)
        except NotAuthorized:
            some_errors = True
            msg = _('Unauthorized to delete user with id "{user_id}". Please check the log files.')
            abort(403, msg.format(user_id=id))

        # Purge CKAN user
        try:
            ckan.model.User.get(user_dict['name']).purge()
            ckan.model.Session.commit()
        except:
            some_errors = True
            h.flash_error(_(' Unable to purge CKAN User.  Please check the log files.'))

        user_index = h.url_for(controller='user', action='index')

        if not some_errors:
            h.flash_success('User ' + user_dict['name'] + ' successfully deleted.')
            h.redirect_to(user_index)
        else:
            h.flash_error ('User ' + user_dict['name'] + ' not entirely deleted. Please check the Log Files')
            h.redirect_to(user_index)

    def _new_form_to_db_schema(self):
        return schema.user_new_form_schema()

    def register(self, data=None, errors=None, error_summary=None):
        context = {'model': model, 'session': model.Session, 'user': c.user,
                   'auth_user_obj': c.userobj}
        try:
            check_access('user_create', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to register as a user.'))

        # Check register Method
        auto = config.get('ckanext.ldap.auto')

        if auto=='true':
            # Automatic registration
            return self._auto_register_request(data, errors, error_summary)
        else:
            # With manual procedure by the CCCA Team
            return self.new_mail_request(data, errors, error_summary)


######################################################################
# Anja 24.9.2018: Automatic Registration including Email Verification

    def _auto_register_request(self, data=None, errors=None, error_summary=None):
        '''GET to display a form for registering a new user.
           Including Email Verification
        '''

        context = {'model': model, 'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj,
                   'schema': self._new_form_to_db_schema(),
                   'save': 'save' in request.params}

        try:
            result = check_access('user_create', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to create a user'))

        if context['save'] and not data:
            return self._request_auto_user(context)

        if c.user and not data:
            # #1799 Don't offer the registration form if already logged in
            return render('user/logout_first.html')

        data = data or {}
        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary}

        c.is_sysadmin = authz.is_sysadmin(c.user)
        c.form = render(self.new_user_form, extra_vars=vars)
        return render('user/new.html')


    def _request_auto_user(self, context):

        try:
            data_dict = logic.clean_dict(unflatten(
                logic.tuplize_dict(logic.parse_params(request.params))))
            context['message'] = data_dict.get('log_message', '')
            captcha.check_recaptcha(request)

            # check for unique email addresses within our system
            # i.e. every email only once
            new_mail = u''
            full_name = u''
            user_name = u''
            for k,v in data_dict.iteritems():
                if (k == 'email'):
                    new_mail = v
                if (k == 'fullname'):
                    full_name = v
                if (k == 'name'):
                    user_name = v

            if full_name == u'':
                error_msg = _(u'Please insert full name.')
                h.flash_error(error_msg)
                return self._auto_register_request(data_dict)
            if user_name == u'':
                error_msg = _(u'Please insert a username.')
                h.flash_error(error_msg)
                return self._auto_register_request(data_dict)
            if new_mail == u'':
                error_msg = _(u'Please insert a valid mail address.')
                h.flash_error(error_msg)
                return self._auto_register_request(data_dict)

            # ATTENTION: This action requires that userlist is available for anon users!
            u_list = p.toolkit.get_action('user_list')({},{"order_by": "email"})


            # need to access the ckan email_hash
            otto = model.User(email=new_mail)
            #print otto.email_hash
            for x in u_list:
                if x['email_hash'] == otto.email_hash:
                    error_msg = _(u'Error: Email Address already registered: ' + new_mail + '.  If you are insecure about this message please contact us: datenzentrum@ccca.ac.at')
                    h.flash_error(error_msg)
                    return self._auto_register_request(data_dict)

            # end check email unique


            # Add ldap and ckan user
            res =  _add_ldap_and_ckan_user(context, data_dict)

            if not res:
                error_msg = _(u'Internal Error. Please try again later or contact datenzentrum@ccca.ac.at')
                h.flash_error(error_msg)
                return self._auto_register_request(data_dict)
            # Actual add End

        except NotAuthorized, e:
            log.error (e)
            error_msg = _(u'Username already exists, use another one.')
            h.flash_error(error_msg)
            return self._auto_register_request(data_dict)
        except NotFound, e:
            abort(404, _('User not found'))
        except DataError:
            abort(400, _(u'Integrity Error'))
        except captcha.CaptchaError:
            error_msg = _(u'Bad Captcha. Please try again.')
            h.flash_error(error_msg)
            return self._auto_register_request(data_dict)
        except EnvironmentError, e:
            errors={}
            errors['Message'] = 'Internal Problem; please try again in a few minutes'
            return self._auto_register_request(data_dict, errors, errors)
        except ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self._auto_register_request(data_dict, errors, error_summary)

        user_obj = user_obj = model.User.get(res['id'])
        # print "**************** request_auto_user"
        # print user_obj
        # print context

        #Send confirmation link to user
        mailer.send_confirm_link(user_obj)

        #Send register information to admins
        send_from = 'new_user@data.ccca.ac.at'
        send_to = ['datenzentrum@ccca.ac.at']
        subject = 'New User: ' + data_dict['name']
        text = 'A new user registered: Username ' + str(data_dict['name']) + ', fullname: ' + str(data_dict['fullname']) + ', Mailadress: '+ str(data_dict['email'])
        _send_mail(send_from, send_to, subject, text)

        #End and success
        h.flash_success('''You registered succesfully to the CCCA Datacentre.
        Please check your inbox for the verification of your email-address.''')
        return render('user/login.html')

# Anja 24.9.2018: Automatic Registration including Email Verification -END
######################################################################

    def new_mail_request(self, data=None, errors=None, error_summary=None):
        '''GET to display a form for registering a new user.
           or POST the form data to actually mail the user
           ldif file to side admin.
        '''

        context = {'model': model, 'session': model.Session,
                   'user': c.user,
                   'auth_user_obj': c.userobj,
                   'schema': self._new_form_to_db_schema(),
                   'save': 'save' in request.params}

        try:
            check_access('user_create', context)
        except NotAuthorized:
            abort(403, _('Unauthorized to create a user'))

        if context['save'] and not data:
            return self._request_user(context)

        if c.user and not data:
            # #1799 Don't offer the registration form if already logged in
            return render('user/logout_first.html')

        data = data or {}
        errors = errors or {}
        error_summary = error_summary or {}
        vars = {'data': data, 'errors': errors, 'error_summary': error_summary}

        c.is_sysadmin = authz.is_sysadmin(c.user)
        c.form = render(self.new_user_form, extra_vars=vars)
        return render('user/new.html')

    def _request_user(self, context):
        try:
            data_dict = logic.clean_dict(unflatten(
                logic.tuplize_dict(logic.parse_params(request.params))))
            context['message'] = data_dict.get('log_message', '')
            captcha.check_recaptcha(request)

            # check for unique email addresses within our system
            # i.e. every email only once
            new_mail = u''
            full_name = u''
            for k,v in data_dict.iteritems():
                if (k == 'email'):
                    new_mail = v
                if (k == 'fullname'):
                    full_name = v

            if full_name == u'':
                error_msg = _(u'Please insert full name.')
                h.flash_error(error_msg)
                return self.new_mail_request(data_dict)
            #print new_mail
            if new_mail == u'':
                error_msg = _(u'Please insert a valid mail address.')
                h.flash_error(error_msg)
                return self.new_mail_request(data_dict)

            #print "HEre we are"
            # ATTENTION: This action requires that userlist is available for anon users!
            u_list = p.toolkit.get_action('user_list')({},{"order_by": "email"})

            #print "HEre we are 2"

            # need to access the ckan email_hash
            otto = model.User(email=new_mail)
            #print otto.email_hash
            for x in u_list:
                if x['email_hash'] == otto.email_hash:
                    error_msg = _(u'Error: Email Address already registered: ' + new_mail + '.  If you are insecure about this message please contact us: datenzentrum@ccca.ac.at')
                    h.flash_error(error_msg)
                    return self.new_mail_request(data_dict)

            # end check email unique

            path = config.get('ckanext.ccca.path_for_ldifs')

            send_from = 'new_user@data.ccca.ac.at'
            send_to = ['datenzentrum@ccca.ac.at']

            subject = 'New user request CKAN: ' + data_dict['name']

            if path is None:
                error_msg = _(u'path_for_ldifs not defined.')
                h.flash_error(error_msg)
                return self.new_mail_request(data_dict)

            if os.path.exists(path + '/' + data_dict['name'] + '.ldif'):

                error_msg = _('Username alreay exists, use another one.')
                h.flash_error(error_msg)
                return self.new_mail_request(data_dict)

            #print "HEre we are 2"

            text = '''
             A new user registered.
             You can find the file here: ''' + path + '''
             and it is called: ''' + data_dict['name']+'.ldif' + '''
             Create user on your LDAP Server with the following command:
             adduser_ldap_ckan.sh HOST FILE APIKey'''

            _make_ldif(context, data_dict, config.get('ckanext.ccca.path_for_ldifs') + '/' + data_dict['name']+'.ldif')
            #print "Here we are 3"
            _send_mail(send_from, send_to, subject, text)

        except NotAuthorized, e:
            log.error (e)
            error_msg = _(u'Username already exists, use another one.')
            h.flash_error(error_msg)
            return self.new_mail_request(data_dict)
        except NotFound, e:
            abort(404, _('User not found'))
        except DataError:
            abort(400, _(u'Integrity Error'))
        except captcha.CaptchaError:
            error_msg = _(u'Bad Captcha. Please try again.')
            h.flash_error(error_msg)
            return self.new_mail_request(data_dict)
        except EnvironmentError, e:
            errors={}
            errors['Message'] = 'Internal Problem; please try again in a few minutes'
            return self.new_mail_request(data_dict, errors, errors)
        except ValidationError, e:
            errors = e.error_dict
            error_summary = e.error_summary
            return self.new_mail_request(data_dict, errors, error_summary)
        except IOError:
            error_msg = _(u'path_for_ldifs not correctly defined.')
            h.flash_error(error_msg)
            return self.new_mail_request(data_dict)

        h.flash_success('''Your request was delivered to the CCCA Datacentre.
        It will be processed within the upcoming working days.''')
        return render('user/login.html')

    def perform_reset(self, id):
        # FIXME 403 error for invalid key is a non helpful page
        context = {'model': ckan.model, 'session': ckan.model.Session,
                   'user': id,
                   'keep_email': True}

        try:
            check_access('user_reset', context)
        except NotAuthorized:
            abort(401, _('Unauthorized to reset password.'))

        try:
            data_dict = {'id': id}
            user_dict = p.toolkit.get_action('user_show')(context, data_dict)

            user_obj = context['user_obj']
        except NotFound, e:
            abort(404, _('User not found'))

        c.reset_key = request.params.get('key')
        if not mailer.verify_reset_link(user_obj, c.reset_key):
            h.flash_error(_('Invalid reset key. Please try again.'))
            abort(403)

        # After the user klicked "submit" - request.method = POST!
        if request.method == 'POST':
            try:
                context['reset_password'] = True
                new_password = self._get_form_password()
                user_dict['password'] = new_password
                user_dict['reset_key'] = c.reset_key
                user_dict['state'] = model.State.ACTIVE

                # NEW: 7.9.18, ANJA - Change LDAP Passwd
                ldap_user_dict = _find_ldap_user(user_dict['name'])
                if ldap_user_dict:
                    ldap_user_dict['userPassword'] = user_dict['password']
                    ret = _change_ldap_user_passwd(ldap_user_dict)
                else:
                    h.flash_error(_('LDAP User not found'))
                # ORIGINAL:
                #    user = get_action('user_update')(context, user_dict)
                #    mailer.create_reset_key(user_obj)

                if ret:
                    # Inform us about reset
                    send_from = 'password_reset@data.ccca.ac.at'
                    send_to = ['datenzentrum@ccca.ac.at']
                    subject = 'Passwort Reset: ' + user_dict['name']
                    text = 'User ' + user_dict['name'] +  ' performed a password reset'
                    _send_mail(send_from, send_to, subject, text)
                    mailer.create_reset_key(user_obj) # Anja: Maybe just to make the old link invalid?
                    h.flash_success(_("Your password has been reset."))
                    h.redirect_to('/')

            except NotAuthorized:
                h.flash_error(_('Unauthorized to edit user %s') % id)
            except NotFound, e:
                h.flash_error(_('User not found'))
            except DataError:
                h.flash_error(_(u'Integrity Error'))
            except ValidationError, e:
                h.flash_error(u'%r' % e.error_dict)
            except ValueError, ve:
                h.flash_error(unicode(ve))

        c.user_dict = user_dict
        return render('user/perform_reset.html')

    def _get_form_password(self):
        password1 = request.params.getone('password1')
        password2 = request.params.getone('password2')
        if (password1 is not None and password1 != ''):
            if not len(password1) >= 4:
                raise ValueError(_('Your password must be 4 '
                                 'characters or longer.'))
            elif not password1 == password2:
                raise ValueError(_('The passwords you entered'
                                 ' do not match.'))
            return password1
        raise ValueError(_('You must provide a password'))

    def confirm_mail(self,id):
        context = {'model': ckan.model, 'session': ckan.model.Session,
                   'user': id,
                   'keep_email': True}

        try:
            data_dict = {'id': id}
            user_dict = p.toolkit.get_action('user_show')(context, data_dict)

            user_obj = context['user_obj']
        except NotFound, e:
            abort(404, _('User not found'))

        c.reset_key = request.params.get('key')
        if not mailer.verify_confirm_link(user_obj, c.reset_key):
            h.flash_error(_('Invalid confirmation key. Please try again.'))
            abort(403)

        success = False
        try:
            user_dict['state'] = model.State.ACTIVE
            # Set reset_key in order to allow default CKAN auth function to pass update
            user_dict['reset_key'] = c.reset_key
            user = p.toolkit.get_action('user_update')(context, user_dict)
            mailer.create_confirm_key(user_obj)  # create new key to make the old invalid
            success = True

            # ORIGINAL - perform_reset:
            # context['reset_password'] = True
            # new_password = self._get_form_password()
            # user_dict['password'] = new_password
            # user_dict['reset_key'] = c.reset_key
            # user_dict['state'] = model.State.ACTIVE
            # user = get_action('user_update')(context, user_dict)
            # mailer.create_reset_key(user_obj) # Anja: Maybe just to make the old link invalid?


        except NotAuthorized:
            h.flash_error(_('Unauthorized to edit user %s') % id)
        except NotFound, e:
            h.flash_error(_('User not found'))
        except DataError:
            h.flash_error(_(u'Integrity Error'))
        except ValidationError, e:
            h.flash_error(u'%r' % e.error_dict)
        except ValueError, ve:
            h.flash_error(unicode(ve))

        c.user_dict = user_dict
        if success:
            h.flash_success(_("Email adress succesfully confirmed. Feel free to login now."))

        return render('user/login.html')

    def login_handler(self):
        """Action called when login via the LDAP login form"""

        params = request.POST
        #print params

        if 'login' in params and 'password' in params:
            login = params['login']
            password = params['password']
            if not password: # ldap does not allow emtpy password; Anja 21.6.2017
                self._login_failed(error=_('Please enter a username and password'))

            # Anja, 21.9.2018 - check the user state!
            user_dict = {}
            try:
                user_dict = p.toolkit.get_action('user_show')(data_dict = {'id': login})
            except:
                pass # It is checked below

            if not user_dict:
                return self._login_failed(error=_('Unknown User. Please register first or contact datenzentrum@ccca.ac.at if you are uncertain about this message'))
            if user_dict:
                if user_dict['state'] == 'waiting':  # waiting for email confirmation
                    return self._login_failed(error=_('Your Email Adress is not yet verified. Please check your inbox for the email confirmation link'))

            try:
                ldap_user_dict = _find_ldap_user(login)
            except MultipleMatchError as e:
                # Multiple users match. Inform the user and try again.
                return self._login_failed(notice=str(e))
            except EnvironmentError as e:
                return self._login_failed(error=_('Some internal problem; please try again in a few minutes'))
            if ldap_user_dict and _check_ldap_password(ldap_user_dict['cn'], password):
                try:
                    user_name = _get_or_create_ldap_user(ldap_user_dict)
                except UserConflictError as e:
                    return self._login_failed(error=str(e))
                return self._login_success(user_name)
            elif ldap_user_dict:
                # There is an LDAP user, but the auth is wrong. There could be a CKAN user of the
                # same name if the LDAP user had been created later - in which case we have a
                # conflict we can't solve.
                if config['ckanext.ldap.ckan_fallback']:
                    exists = _ckan_user_exists(login)
                    if exists['exists'] and not exists['is_ldap']:
                        return self._login_failed(error=_('Username conflict. Please contact the site administrator.'))
                return self._login_failed(error=_('Bad username or password.'))
            elif config['ckanext.ldap.ckan_fallback']:
                # No LDAP user match, see if we have a CKAN user match
                try:
                    user_dict = p.toolkit.get_action('user_show')(data_dict = {'id': login})
                    # We need the model to validate the password
                    user = User.by_name(user_dict['name'])
                except p.toolkit.ObjectNotFound:
                    user = None
                if user and user.validate_password(password):
                    return self._login_success(user.name)
                else:
                    #print "********* Anja 1"
                    return self._login_failed(error=_('Bad username or password.'))
            else:
                return self._login_failed(error=_('Bad username or password.'))
        return self._login_failed(error=_('Please enter a username and password'))

    def _login_failed(self, notice=None, error=None):
        """Handle login failures

        Redirect to /user/login and flash an optional message

        @param notice: Optional notice for the user
        @param error: Optional error message for the user
        """
        if notice:
            flash_notice(notice)
        if error:
            flash_error(error)
        p.toolkit.redirect_to(controller='user', action='login')

    def _login_success(self, user_name):
        """Handle login success

        Saves the user in the session and redirects to user/logged_in

        @param user_name: The user name
        """
        pylons.session['ckanext-ldap-user'] = user_name
        pylons.session.save()
        p.toolkit.redirect_to(controller='user', action='dashboard', id=user_name)

#############################################################################
# Methods for auto register - Anja, 26.9.2018
def _get_ldap_ids():

    #Bind as Admin
    cnx = ldap.initialize(config['ckanext.ldap.uri'])

    if config.get('ckanext.ldap.auth.dn'):
        try:
            cnx.bind_s(config['ckanext.ldap.auth.dn'], config['ckanext.ldap.auth.password'])
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            _send_ldap_error_mail('LDAP server is not reachable')
            return None
        except ldap.INVALID_CREDENTIALS:
            log.error('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            _send_ldap_error_mail('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            return None

    #res = cnx.search_s("dc=blah,dc=blah", ldap.SCOPE_SUBTREE, 'objectclass=posixaccount', ['uidNumber'])
    try:
        res = cnx.search_s(config['ckanext.ldap.base_dn'], ldap.SCOPE_SUBTREE,'objectclass=posixaccount', ['uidNumber','gidNumber'])
    except ldap.SERVER_DOWN:
        log.error('LDAP server is not reachable')
        return None
    except ldap.OPERATIONS_ERROR as e:
        log.error('LDAP query failed. Maybe you need auth credentials for performing searches? Error returned by the server: ' + e.info)
        return None
    except (ldap.NO_SUCH_OBJECT, ldap.REFERRAL) as e:
        log.error('LDAP distinguished name (ckanext.ldap.base_dn) is malformed or does not exist.')
        return None
    except ldap.FILTER_ERROR:
        log.error('LDAP filter (ckanext.ldap.search) is malformed')
        return None

    uidNum = 0
    gidNum = 0

    for a in res:
        uidNumtemp = a[1].get('uidNumber')[0]
        if uidNumtemp > uidNum:
           uidNum = uidNumtemp
        gidNumtemp = a[1].get('gidNumber')[0]
        if gidNumtemp > gidNum:
           gidNum = gidNumtemp

    #print uidNum
    #print gidNum
    if uidNum >0 and gidNum > 0:
        return [int(uidNum)+1, int(gidNum)+1]
    else:
        return None


def _add_ldap_and_ckan_user(context, data_dict):
    """
    Create  ldap dict out of user data and add to ldap
    """
    schema = context.get('schema') or logic.schema.default_user_schema()
    #schema = context.get('schema') or logic.schema.user_new_form_schema()
    session = context['session']

    try:
        r = check_access('user_create', context, data_dict)
        print "check_access " + str(r)
    except:
        session.rollback()
        raise ValidationError('Unauthorized to create a user')

    user_name = _get_unique_user_name_check_ldap(data_dict['name'])
    data_dict['name'] = user_name

    data, errors = _validate(data_dict, schema, context)

    # FIXME : rolback nur hier?
    if errors:
        session.rollback()
        raise ValidationError(errors)

    ids = _get_ldap_ids()

    if ids:
        uid =  str(ids[0])
        gid =  str(ids[1])

    if not uid or not gid:
        session.rollback()
        raise ValidationError("Please try again later")

    #Bind as Admin
    cnx = ldap.initialize(config['ckanext.ldap.uri'])

    if config.get('ckanext.ldap.auth.dn'):
        try:
            cnx.bind_s(config['ckanext.ldap.auth.dn'], config['ckanext.ldap.auth.password'])
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            _send_ldap_error_mail('LDAP server is not reachable')
            return None
        except ldap.INVALID_CREDENTIALS:
            log.error('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            _send_ldap_error_mail('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            return None

    hash_password = _make_secret(data_dict['password1'])

    ldap_data_dict = dict((k, v.encode('utf-8')) for (k, v) in data_dict.items())

    # Create ldap user
    try:
        entry_user = {'objectClass': ['top', 'person', 'organizationalPerson',
                                      'inetOrgPerson', 'posixAccount', 'shadowAccount',
                                      'ldapPublicKey'],
                      'uid': [ldap_data_dict['name']],
                      'cn': [ldap_data_dict['fullname']],
                      'sn': [ldap_data_dict['fullname'].split()[-1]] if ldap_data_dict['fullname'] else [''],
                      'givenName': [' '.join(ldap_data_dict['fullname'].split()[:-1])],
                      'mail': [ldap_data_dict['email']],
                      'userPassword': [hash_password],
                      'loginShell': ['/usr/bin/mysecureshell'],
                      'uidNumber': [uid],
                      'gidNumber': [gid],
                      'homeDirectory': ['/e/user/home/' + ldap_data_dict['name']],
                      'sshPublicKey': [ldap_data_dict['sshkey']]}
        dn_user = 'uid='+str(ldap_data_dict['name'])+',ou=people,dc=ldap,dc=ccca,dc=ac,dc=at'

        #test = ldap.modlist.addModlist(entry_user)
        #print test
        #print entry_user
        #print _find_ldap_user(user_name)
        result = cnx.add_s(dn_user, ldap.modlist.addModlist(entry_user))
    except:
        log.error('Error creating LDAP User:' + str(ldap_data_dict['name']))
        _send_ldap_error_mail('Error creating LDAP User: ' + str(ldap_data_dict['name']))
        cnx.unbind()
        return None

    #print result

    # Create LDAP user group
    try:
        dn_group = 'cn='+str(ldap_data_dict['name'])+',ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
        entry_group = {'objectClass': ['posixGroup'],
                       'cn': [ldap_data_dict['name']],
                       'gidNumber': [gid],
                       'memberUid': [ldap_data_dict['name']]}
        result = cnx.add_s(dn_group, ldap.modlist.addModlist(entry_group))

    except:
        log.error('Error creating LDAP User Group:' + str(ldap_data_dict['name']))
        _send_ldap_error_mail('Error creating LDAP User Group: ' + str(ldap_data_dict['name']))
        cnx.unbind()
        return None

    # Add user to general user group
    try:
        dn_group_users = 'cn=users,ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
        entry_group_users = [(ldap.MOD_ADD,'memberUid',[ldap_data_dict['name']])]
        #result = cnx.modify_s(dn_group_users, ldap.modlist.addModlist(entry_group_users))
        result = cnx.modify_s(dn_group_users, entry_group_users)
    except:
        log.error('Error adding LDAP User to General User Group: '  + str(ldap_data_dict['name']))
        _send_ldap_error_mail('Error adding LDAP User to General User Group: ' + str(ldap_data_dict['name']))
        cnx.unbind()
        return None

    cnx.unbind()

    #########################################################
    # Now CKAN
    # Store ldap dict
    try:
        ldap_user_dict = _find_ldap_user(data_dict['name'])
    except NotFound, e:
        log.error('LDAP User not found:' + str(data_dict['name']))
        h.flash_error(_('LDAP User not found. Please contact datenzentrum@ccca.ac.at.'))
        return None

    data_dict['state'] = 'waiting'

    try:
        ckan_user = p.toolkit.get_action('user_create')(context=context, data_dict=data_dict)
    except:
        log.error('Error creating CKAN USER: '  + data_dict['name'])
        _send_ldap_error_mail('Error creating CKAN USER: ' + data_dict['name'])

        # try and remove ldap user again
        try:
            if ldap_user_dict:
                _delete_ldap_user(ldap_user_dict)
                log.error('LDAP User deleted because of errors creating CKAN user '  + data_dict['name'])
        except:
                log.error('Error removing LDAP User: '  + data_dict['name'])

        return None

    # Add LdapUser entry = Database entry with match ckan_id - ldap_id
    # FIXME: Break/rollback if it does not work?
    try:
        ldap_user = LdapUser(user_id=ckan_user['id'], ldap_id = ldap_user_dict['username'])
        ckan.model.Session.add(ldap_user)
        ckan.model.Session.commit()
    except:
        log.error('Error adding user to CKAN LdapUser Table:' + str(ckan_user[name]))
        _send_ldap_error_mail('Error adding user to CKAN LDAP User Table:' + str(ckan_user[name]) )
        return None


    # Add the user to it's group if needed - JUST ONE LDAP SPECIFC ORGANIZATION - not for us; Anja 21.6.17
    try:
        if 'ckanext.ldap.organization.id' in config:
            p.toolkit.get_action('member_create')(
                context={'ignore_auth': False},
                data_dict={
                    'id': config['ckanext.ldap.organization.id'],
                    'object': user_name,
                    'object_type': 'user',
                    'capacity': config['ckanext.ldap.organization.role']
                }
            )
    except:
        log.error('Error with CKAN DEFAULT Organization')


    # Check the users email adress and add it to the appropiate organization as Editor
    #print ldap_user_dict['email']
    #FIXME: Check this first if we only want CCCA members
    user_org = check_mail_org(data_dict['email'])

    # FIXME: Maybe not for anon users?
    if not user_org:
        # check ccca-extern
        if 'ckanext.iauth.special_org' in config:
            user_org = config.get( 'ckanext.iauth.special_org')
            #print "************ 2"

            #print user_org
            # check if org exists
            try:
                check_org = tk.get_action('organization_show')(context, {'id':user_org})
            except:
                user_org = None
                pass

    if user_org:
        try:
            p.toolkit.get_action('member_create')(
                context={'ignore_auth': True},
                data_dict={
                    'id': user_org,
                    'object': user_name,
                    'object_type': 'user',
                    'capacity': 'editor'
                }
            )
        except:
            log.error('Error adding user to organization: ' + str(user_org) +  ', '  + str(user_name))

    return ckan_user
# Ende Auto
##################################################################

def _ckan_ldap_user_exists(user_name):
    """Check if a CKAN user name exists, and if that user is an LDAP user.

    @param user_name: User name to check
    @return: Dictionary defining 'exists' and 'ldap'.
    """
    try:
        user = p.toolkit.get_action('user_show')(data_dict = {'id': user_name})
    except p.toolkit.ObjectNotFound:
        # Check ldap
        # Get LDAP User dict
        try:
            ldap_user_dict = _find_ldap_user(user_name)
        except NotFound, e:
            return {'exists': False}
        if ldap_user_dict:
            return {'exists': True}
        else:
            return {'exists': False}

    return {'exists': True}

def _get_unique_user_name_check_ldap (base_name):
    """Create a unique, valid, non existent user name from the given base name

    @param base_name: Base name
    @return: A valid user name not currently in use based on base_name
    """
    base_name = re.sub('[^-a-z0-9_]', '_', base_name.lower())
    base_name = base_name[0:100]
    if len(base_name) < 2:
        base_name = (base_name + "__")[0:2]
    count = 0
    user_name = base_name
    while (_ckan_ldap_user_exists(user_name))['exists']:
        count += 1
        user_name = "{base}{count}".format(base=base_name[0:100-len(str(count))], count=str(count))
    return user_name

def _ckan_user_exists(user_name):
    """Check if a CKAN user name exists, and if that user is an LDAP user.

    @param user_name: User name to check
    @return: Dictionary defining 'exists' and 'ldap'.
    """

    try:
        user = p.toolkit.get_action('user_show')(data_dict = {'id': user_name})
    except p.toolkit.ObjectNotFound:
        #print "Here we are"
        return {'exists': False, 'is_ldap': False}

    ldap_user = LdapUser.by_user_id(user['id'])

    if ldap_user:
        return {'exists': True, 'is_ldap': True}
    else:
        return {'exists': True, 'is_ldap': False}

def _get_unique_user_name(base_name):
    """Create a unique, valid, non existent user name from the given base name

    @param base_name: Base name
    @return: A valid user name not currently in use based on base_name
    """
    base_name = re.sub('[^-a-z0-9_]', '_', base_name.lower())
    base_name = base_name[0:100]
    if len(base_name) < 2:
        base_name = (base_name + "__")[0:2]
    count = 0
    user_name = base_name
    while (_ckan_user_exists(user_name))['exists']:
        count += 1
        user_name = "{base}{count}".format(base=base_name[0:100-len(str(count))], count=str(count))
    return user_name


def _get_or_create_ldap_user(ldap_user_dict):
    """Get or create a CKAN user from the data returned by the LDAP server

    @param ldap_user_dict: Dictionary as returned by _find_ldap_user
    @return: The CKAN username of an existing user
    """
    # Look for existing user, and if found return it.
    ldap_user = LdapUser.by_ldap_id(ldap_user_dict['username'])

    if ldap_user:
        # TODO: Update the user detail.
        return ldap_user.user.name
    # Check whether we have a name conflict (based on the ldap name, without mapping it to allowed chars)
    exists = _ckan_user_exists(ldap_user_dict['username'])
    if exists['exists'] and not exists['is_ldap']:
        raise UserConflictError(_('There is a username conflict. Please inform the site administrator.'))
    # If a user with the same ckan name already exists but is an LDAP user, this means (given that we didn't
    # find it above) that the conflict arises from having mangled another user's LDAP name. There will not
    # however be a conflict based on what is entered in the user prompt - so we can go ahead. The current
    # user's id will just be mangled to something different.

    # Now get a unique user name, and create the CKAN user and the LdapUser entry.
    user_name = _get_unique_user_name(ldap_user_dict['username'])
    user_dict = {
        'name': user_name,
        'email': ldap_user_dict['email'],
        'password': str(uuid.uuid4())
    }
    if 'fullname' in ldap_user_dict:
        user_dict['fullname'] = ldap_user_dict['fullname']
    if 'about' in ldap_user_dict:
        user_dict['about'] = ldap_user_dict['about']
    ckan_user = p.toolkit.get_action('user_create')(
        context={'ignore_auth': True},
        data_dict=user_dict
    )
    ldap_user = LdapUser(user_id=ckan_user['id'], ldap_id = ldap_user_dict['username'])

    ckan.model.Session.add(ldap_user)
    ckan.model.Session.commit()
    # Add the user to it's group if needed
    if 'ckanext.ldap.organization.id' in config:
        p.toolkit.get_action('member_create')(
            context={'ignore_auth': True},
            data_dict={
                'id': config['ckanext.ldap.organization.id'],
                'object': user_name,
                'object_type': 'user',
                'capacity': config['ckanext.ldap.organization.role']
            }
        )
    return user_name

def _change_ldap_user_passwd(ldap_user_dict):
    """ Set the Password of the user to the value given in 'userPassword'

    @param ldap_user_dict: Ldap User Dict including 'cn' and 'userPassword'
    @return: True if success False otherwise
    """
    #Bind as Admin
    cnx = ldap.initialize(config['ckanext.ldap.uri'])

    if config.get('ckanext.ldap.auth.dn'):
        try:
            cnx.bind_s(config['ckanext.ldap.auth.dn'], config['ckanext.ldap.auth.password'])
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            _send_ldap_error_mail('LDAP server is not reachable')
            raise EnvironmentError({ 'LDAP server': 'is not reachable'})
            #return None
        except ldap.INVALID_CREDENTIALS:
            log.error('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            _send_ldap_error_mail('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            raise EnvironmentError({ 'LDAP server': 'credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid'})
            #return None

    try:
        dn = ldap_user_dict['cn']
        cnx.passwd_s(dn, None,ldap_user_dict['userPassword'] )

    except:
        log.error('LDAP: Error changing password')
        cnx.unbind()
        return False

    cnx.unbind()
    return True

def _delete_ldap_user(ldap_user_dict):

    #Bind as Admin
    cnx = ldap.initialize(config['ckanext.ldap.uri'])

    if config.get('ckanext.ldap.auth.dn'):
        try:
            cnx.bind_s(config['ckanext.ldap.auth.dn'], config['ckanext.ldap.auth.password'])
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            _send_ldap_error_mail('LDAP server is not reachable')
            raise EnvironmentError({ 'LDAP server': 'is not reachable'})
            #return None
        except ldap.INVALID_CREDENTIALS:
            log.error('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            _send_ldap_error_mail('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            raise EnvironmentError({ 'LDAP server': 'credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid'})
            #return None

    dn = ldap_user_dict['cn']

    if  not dn:
        return False
    try:
        # delete user
        cnx.delete_s(dn)
    except:
        log.error('LDAP: Error Deleting User: ' + str(dn) )
        cnx.unbind()
        return False

    try:
        # delete specific user group
        dn_group = 'cn='+str(ldap_user_dict['username'])+',ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
        # entry_group = {'objectClass': ['posixGroup'],
        #                'cn': [data_dict['name']],
        #                'gidNumber': [gid],
        #
        #                'memberUid': [data_dict['name']]}
        result = cnx.delete_s(dn_group)
    except:
        log.error('LDAP: Error Deleting Group: ' + str(dn_group) )
        cnx.unbind()
        return False
    try:
        # delete user from general user group
        dn_group_users = 'cn=users,ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
        entry_group_users = [(ldap.MOD_DELETE,'memberUid',[str(ldap_user_dict['username'])])]
        #result = cnx.modify_s(dn_group_users, ldap.modlist.addModlist(entry_group_users))
        result = cnx.modify_s(dn_group_users, entry_group_users)

    except:
        log.error('LDAP: Error Deleting User From Group: ' + str(dn_group_users) + ' -- ' + str(entry_group_users) )
        cnx.unbind()
        return False

    cnx.unbind()
    return True


def _find_ldap_user(login):
    """Find the LDAP user identified by 'login' in the configured ldap database

    @param login: The login to find in the LDAP database
    @return: None if no user is found, a dictionary defining 'cn', 'username', 'fullname' and 'email otherwise.
    """
    cnx = ldap.initialize(config['ckanext.ldap.uri'])
    #print "************ ANJA LDAP"
    #print login
    if config.get('ckanext.ldap.auth.dn'):
        try:
            cnx.bind_s(config['ckanext.ldap.auth.dn'], config['ckanext.ldap.auth.password'])
        except ldap.SERVER_DOWN:
            log.error('LDAP server is not reachable')
            _send_ldap_error_mail('LDAP server is not reachable')
            raise EnvironmentError({ 'LDAP server': 'is not reachable'})
            #return None
        except ldap.INVALID_CREDENTIALS:
            log.error('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            _send_ldap_error_mail('LDAP server credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid')
            raise EnvironmentError({ 'LDAP server': 'credentials (ckanext.ldap.auth.dn and ckanext.ldap.auth.password) invalid'})
            #return None

    filter_str = config['ckanext.ldap.search.filter'].format(login=ldap.filter.escape_filter_chars(login))
    attributes = [config['ckanext.ldap.username']]
    #print "*************2"
    if 'ckanext.ldap.fullname' in config:
        attributes.append(config['ckanext.ldap.fullname'])
    if 'ckanext.ldap.email' in config:
        attributes.append(config['ckanext.ldap.email'])
    try:
        ret = _ldap_search(cnx, filter_str, attributes, non_unique='log')
        if ret is None and 'ckanext.ldap.search.alt' in config:
            filter_str = config['ckanext.ldap.search.alt'].format(login=ldap.filter.escape_filter_chars(login))
            ret = _ldap_search(cnx, filter_str, attributes, non_unique='raise')
    finally:
        cnx.unbind()

    #print ret
    return ret


def _ldap_search(cnx, filter_str, attributes, non_unique='raise'):
    """Helper function to perform the actual LDAP search

    @param cnx: The LDAP connection object
    @param filter_str: The LDAP filter string
    @param attributes: The LDAP attributes to fetch. This *must* include self.ldap_username
    @param non_unique: What to do when there is more than one result. Can be either 'log' (log an error
                       and return None - used to indicate that this is a configuration problem that needs
                       to be address by the site admin, not by the current user) or 'raise' (raise an
                       exception with a message that will be displayed to the current user - such
                       as 'please use your unique id instead'). Other values will silently ignore the error.
    @return: A dictionary defining 'cn', self.ldap_username and any other attributes that were defined
             in attributes; or None if no user was found.
    """
    #print "*** ldap search"
    try:
        res = cnx.search_s(config['ckanext.ldap.base_dn'], ldap.SCOPE_SUBTREE, filterstr=filter_str, attrlist=attributes)
    except ldap.SERVER_DOWN:
        log.error('LDAP server is not reachable')
        return None
    except ldap.OPERATIONS_ERROR as e:
        log.error('LDAP query failed. Maybe you need auth credentials for performing searches? Error returned by the server: ' + e.info)
        return None
    except (ldap.NO_SUCH_OBJECT, ldap.REFERRAL) as e:
        log.error('LDAP distinguished name (ckanext.ldap.base_dn) is malformed or does not exist.')
        return None
    except ldap.FILTER_ERROR:
        log.error('LDAP filter (ckanext.ldap.search) is malformed')
        return None
    #print "*********** ldap search 2"
    #print res
    if len(res) > 1:
        if non_unique == 'log':
            log.error('LDAP search.filter search returned more than one entry, ignoring. Fix the search to return only 1 or 0 results.')
        elif non_unique == 'raise':
            raise MultipleMatchError(config['ckanext.ldap.search.alt_msg'])
        return None
    elif len(res) == 1:
        cn = res[0][0]
        attr = res[0][1]
        ret = {
            'cn': cn,
        }

        # Check required fields
        for i in ['username', 'email']:
            cname = 'ckanext.ldap.' + i
            if config[cname] not in attr or not attr[config[cname]]:
                log.error('LDAP search did not return a {}.'.format(i))
                return None
        # Set return dict
        for i in ['username', 'fullname', 'email', 'about']:
            cname = 'ckanext.ldap.' + i
            if cname in config and config[cname] in attr:
                v = attr[config[cname]]
                if v:
                    ret[i] = v[0].decode('utf-8')
        return ret
    else:
        return None


def _check_ldap_password(cn, password):
    """Checkes that the given cn/password credentials work on the given CN.

    @param cn: Common name to log on
    @param password: Password for cn
    @return: True on success, False on failure
    """

    cnx = ldap.initialize(config['ckanext.ldap.uri'])
    try:
        cnx.bind_s(cn, password)
    except ldap.SERVER_DOWN:
        log.error('LDAP server is not reachable')
        return False
    except ldap.INVALID_CREDENTIALS:
        log.debug('Invalid LDAP credentials')
        return False
    cnx.unbind_s()
    return True

def _send_ldap_error_mail(error):
    import smtplib
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.utils import COMMASPACE, formatdate
    from os.path import basename

    ldap_user_dict = None
    send_from = 'test@data.ccca.ac.at'
    #send_from = 'anja.stemme@ccca.ac.at'
    send_to = ['datenzentrum@ccca.ac.at']
    #send_to = ['anja.stemme@ccca.ac.at']
    subject = 'ATTENTION: Potential LDAP Problem'
    text = error

    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))
    try:
        smtp = smtplib.SMTP(config.get('smtp.server'))
        smtp.sendmail(send_from, send_to, msg.as_string())
        smtp.quit()
    except:
        pass



def _send_mail(send_from, send_to, subject, text):
    import smtplib
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.utils import COMMASPACE, formatdate
    from os.path import basename

    assert isinstance(send_to, list)
    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))


    smtp_connection = smtplib.SMTP()
    smtp_server = config.get('smtp.server')
    smtp_starttls = paste.deploy.converters.asbool(
                config.get('smtp.starttls'))
    smtp_user = config.get('smtp.user')
    smtp_password = config.get('smtp.password')

   # smtp = smtplib.SMTP(config.get('smtp.server'))
    smtp_connection.connect(smtp_server)
    try:
        #smtp_connection.set_debuglevel(True)

        # Identify ourselves and prompt the server for supported features.
        smtp_connection.ehlo()

        # If 'smtp.starttls' is on in CKAN config, try to put the SMTP
        # connection into TLS mode.
        if smtp_starttls:
            if smtp_connection.has_extn('STARTTLS'):
                smtp_connection.starttls()
                # Re-identify ourselves over TLS connection.
                smtp_connection.ehlo()
            else:
                raise MailerException("SMTP server does not support STARTTLS")

        # If 'smtp.user' is in CKAN config, try to login to SMTP server.
        if smtp_user:
            assert smtp_password, ("If smtp.user is configured then "
                    "smtp.password must be configured as well.")
            smtp_connection.login(smtp_user, smtp_password)

        smtp_connection.sendmail(send_from, send_to, msg.as_string())
        log.info("Sent email to {0}".format(send_to))

    except smtplib.SMTPException, e:
        msg = '%r' % e
        log.exception(msg)
        raise MailerException(msg)
    finally:
        smtp_connection.quit()


def _make_ldif(context, data_dict, filepath):
    """
    Create ldif file in filepath from data_dict input
    """
    schema = context.get('schema') or logic.schema.default_user_schema()
    #schema = context.get('schema') or logic.schema.user_new_form_schema()
    session = context['session']

    check_access('user_create', context, data_dict)

    data, errors = _validate(data_dict, schema, context)

    if errors:
        session.rollback()
        raise ValidationError(errors)

    hash_password = _make_secret(data_dict['password1'])

    data_dict = dict((k, v.encode('utf-8')) for (k, v) in data_dict.items())
    # Add user
    entry_user = {'objectClass': ['top', 'person', 'organizationalPerson',
                                  'inetOrgPerson', 'posixAccount', 'shadowAccount',
                                  'ldapPublicKey'],
                  'uid': [data_dict['name']],
                  'cn': [data_dict['fullname']],
                  'sn': [data_dict['fullname'].split()[-1]] if data_dict['fullname'] else [''],
                  'givenName': [' '.join(data_dict['fullname'].split()[:-1])],
                  'mail': [data_dict['email']],
                  'userPassword': [hash_password],
                  'loginShell': ['/usr/bin/mysecureshell'],
                  'uidNumber': ['UID'],
                  'gidNumber': ['GID'],
                  'homeDirectory': ['/e/user/home/' + data_dict['name']],
                  'sshPublicKey': [data_dict['sshkey']]}
    dn_user = 'uid='+str(data_dict['name'])+',ou=people,dc=ldap,dc=ccca,dc=ac,dc=at'
    with open(filepath, 'w') as file:
        ldif_writer = ldif.LDIFWriter(file, filepath)
        ldif_writer.unparse(dn_user, entry_user)

    # Add specific user group
    dn_group = 'cn='+str(data_dict['name'])+',ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
    entry_group = {'objectClass': ['posixGroup'],
                   'cn': [data_dict['name']],
                   'gidNumber': ['GID'],
                   'memberUid': [data_dict['name']]}
    with open(filepath, 'a') as file:
        ldif_writer = ldif.LDIFWriter(file, filepath)
        ldif_writer.unparse(dn_group, entry_group)

    # Add user to general user group
    dn_group_users = 'cn=users,ou=groups,dc=ldap,dc=ccca,dc=ac,dc=at'
    entry_group_users = [(ldap.MOD_ADD,'memberUid',[data_dict['name']])]
    with open(filepath, 'a') as file:
        ldif_writer = ldif.LDIFWriter(file, filepath)
        ldif_writer.unparse(dn_group_users, entry_group_users)

    return filepath


def _check_password(tagged_digest_salt, password):
    """
    Checks the OpenLDAP tagged digest against the given password
    """
    # the entire payload is base64-encoded
    assert tagged_digest_salt.startswith('{SSHA}')

    # strip off the hash label
    digest_salt_b64 = tagged_digest_salt[6:]

    # the password+salt buffer is also base64-encoded.  decode and split the
    # digest and salt
    digest_salt = digest_salt_b64.decode('base64')
    digest = digest_salt[:20]
    salt = digest_salt[20:]

    sha = hashlib.sha1(password)
    sha.update(salt)

    return digest == sha.digest()


def _make_secret(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer

    @param password: Password for hashing
    @return: Hashed password
    """
    salt = os.urandom(4)

    # hash the password and append the salt
    sha = hashlib.sha1(password)
    sha.update(salt)

    # create a base64 encoded string of the concatenated digest + salt
    digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()

    # now tag the digest above with the {SSHA} tag
    tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)

    return tagged_digest_salt
