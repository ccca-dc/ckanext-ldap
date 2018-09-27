#!/usr/bin/env python
# encoding: utf-8
"""
Created by 'bens3' on 2013-06-21.
Copyright (c) 2013 'bens3'. All rights reserved.
"""

import pylons

import ldap, ldap.filter
import ckan.model as model
from pylons import config

def check_mail_org(user_email):
    ccca_orgs= [u'mul', u'seri', u'ages', u'ait', u'alps', u'bayerische-akademie-der-wissenschaften', u'bfw-bundesforschungszentrum-fur-wald', u'boku', u'ccca', u'donau-uni',u'essl', u'gba', u'iiasa', u'iio', u'jr', u'oaw', u'ogm', u'tu-graz', u'tu-wien',  u'uibk', u'uni-salzburg', u'uni-wien', u'vetmeduni', u'uni-graz', u'wifo', u'wp', u'wu', u'zamg', u'zsi']
    ccca_mails = [u'unileoben.ac.at', u'seri.at', u'ages.at',u'ait.ac.at',u'alps-gmbh.com',u'badw.de',u'bfw.gv.at',u'boku.ac.at', u'ccca.ac.at', u'donau-uni.ac.at', u'essl.org',u'geologie.ac.at',u'iiasa.ac.at',u'indoek.at',u'joanneum.at', u'oeaw.ac.at', u'meteorologie.at', u'tugraz.at', u'tuwien.ac.at',u'uibk.ac.at',u'sbg.ac.at', u'univie.ac.at',u'vetmeduni.ac.at', u'uni-graz.at', u'wifo.ac.at', u'weatherpark.com', u'wu.ac.at',u'zamg.ac.at', u'zsi.at']

    #print len (ccca_orgs)
    #print len(ccca_mails)
    mail_to_check = user_email.split('@')
    if len(mail_to_check)>1:
        mail_to_check = mail_to_check[1]
    else:
        return None
    #print mail_to_check

    if mail_to_check in ccca_mails:
        #print "success"
        org_index = ccca_mails.index(mail_to_check)
        #print ccca_orgs[org_index]
        return ccca_orgs[org_index]
    else:
        # check if subdomain
        if config.get('ckanext.ldap.mail_prefix'):
            prefixes = config['ckanext.ldap.mail_prefix']
            #print prefixes
            dot_i = mail_to_check.find('.')
            if dot_i > 0:
                subdo = mail_to_check[0:dot_i]
                if subdo not in prefixes:
                    return None

                mail_to_check = mail_to_check[dot_i+1:]

                #print mail_to_check
                if mail_to_check in ccca_mails:
                    #print "success"
                    org_index = ccca_mails.index(mail_to_check)
                    #print ccca_orgs[org_index]
                    return ccca_orgs[org_index]

    #print "leider nicht"
    return None

def is_ldap_user():
    """
    Help function for determining if current user is LDAP user
    @return: boolean
    """
    #print "Anja is_ldap_user"
    #print pylons.session
    return 'ckanext-ldap-user' in pylons.session
