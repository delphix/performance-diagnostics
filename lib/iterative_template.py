#
# Copyright 2019 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import re
from string import Template


class IterativeTemplate:
    """ The IterativeTemplate class builds on python string
    templates to allow iteration to substitute multiple lines
    for a single template variable as well as simple
    substitutions.
    For example, consider the case where following string is the
    input template string used to initialize the object.

    pretemplate string
    $hists:{hist|
    helper.add_am.group(2)("$hist.name$", BCCHelper.$hist.aggtype$)
    }$
    postemplate string

    When the render method is called the first and last line would
    pass through unchanged. The three central lines indicate an
    iterative substituion will be performed.  A "hists" group should
    have been added will 1 or field dict added to the group.  Each
    dict is expected to contain the fields "name" and "aggtype".  A
    line will be generated for each field substituting the values in
    the dictionary for the specified fields.
    """
    #
    # The TOP_ITERATIVE_REGEX matches template loops and identifies
    # group1 as the name and group2 is the bracketted part of the
    # template loop with the loop variable declaration and the
    # loop text.  For example:
    # group0:
    # -------
    # $hists:{hist|
    # helper.add_am.group(2)("$hist.name$", BCCHelper.$hist.aggtype$)
    # }$
    # group1:
    # -------
    # hists
    # group2:
    # -------
    # {hist|
    # helper.add_am.group(2)("$hist.name$", BCCHelper.$hist.aggtype$)
    # }
    #
    TOP_ITERATIVE_REGEX = r"\$(\w+)\:(\{\w+\|[^}]*})\$"

    #
    # The org.stringtemplate.v4 used int he scripts requires dollars
    # signs around template variables, e.g. $var$.  The trailing
    # dollar sign is removed to work with python string templates
    # using DOUBLE_DOLLAR_REGEX.
    #
    DOUBLE_DOLLAR_REGEX = r"\$\w+?(\$)"

    def __init__(self, templateString):
        """ Initialize by saving the string to perform substitutions on
        and initializing the dictionaries that will hold fields to
        substutitute.
        """
        self.templateString = templateString
        self.mappingGroups = dict()
        self.singletons = dict()

    def addFields(self, groupName, fields):
        """ Add dicts containing the fields to substitute to the
        specified group.  The groups with multiple values can be
        iterated over to perform substution.
        """
        if groupName in self.mappingGroups:
            group = self.mappingGroups[groupName]
        else:
            group = self.IterativeTemplateGroup()
        group.addFieldMapping(fields)
        self.mappingGroups[groupName] = group

    def addSingleton(self, name, value):
        """ Add singleton to do a straight substitution
        """
        self.singletons[name] = value

    def selectFields(self, groupName, fieldNames):
        """ Pass down selections to the group to all a
        a subset of the fields present to be used.
        """
        group = self.mappingGroups[groupName]
        group.selectFields(fieldNames)

    def render(self):
        """ Apply iterative templates """

        str = self.templateString
        m = re.search(self.TOP_ITERATIVE_REGEX, str)
        while m:
            group = self.mappingGroups[m.group(1)]
            str = str[:m.start(0)] \
                + group.applyFields(m.group(2)) \
                + str[m.end(0)+1:]
            m = re.search(self.TOP_ITERATIVE_REGEX, str)

        m = re.search(self.DOUBLE_DOLLAR_REGEX, str)
        if m:
            str = str[:m.start(1)] + str[m.end(1):]

        t = Template(str)
        return t.substitute(self.singletons)

    class IterativeTemplateGroup:
        #
        # VAR_ITERATIVE_REGEX is applied to the bracketed portion of the
        # teamplate loop to identify the loop variable and the loop text.
        # For example:
        # group0
        # -------
        # {hist|
        # helper.add_am.group(2)("$hist.name$", BCCHelper.$hist.aggtype$)
        # }
        #
        # group1
        # -------
        # hist
        #
        # group1
        # -------
        # helper.add_am.group(2)("$hist.name$", BCCHelper.$hist.aggtype$)
        #
        VAR_ITERATIVE_REGEX = r"{(\w+)\|([^}]*)}"

        def __init__(self):
            self.fields = list()
            self.mappingSelections = list()

        def selectFields(self, fieldNames):
            for field in fieldNames:
                self.mappingSelections.append(field)

        def addFieldMapping(self, fields):
            self.fields.append(fields)

        def applyFields(self, instr):
            m = re.search(self.VAR_ITERATIVE_REGEX, instr)
            var = m.group(1) + "."
            #
            # Initialize a python template for the loop text.  Modify all
            # the template field # references to simple python template
            # variables:
            #      $var.field$ -->  $field
            #
            str = m.group(2).replace('$' + var, '@').replace('$', '')
            t = Template(str.replace('@', '$'))
            outstr = ""
            #
            # Do the template subsutituion for each set of fields in the
            # group.  If a set of fields has been selected than apply
            # those in the user-defined set.
            #
            for field in self.fields:
                if not self.mappingSelections or field['name'] \
                   in self.mappingSelections:
                    outstr += t.substitute(field)
            return outstr
