# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Switch and related classes which are data storage
classes related to Switch structures.
"""

import utils

class SwitchAction:
    """
    This class stores data related to a switch action.

    Settable class variables:
        name: action name.
        type: action type
        referenceType: name of the of the referenced structure if type is of
            "bits", "enum", "object", "switch", or "list".
        elementType: the type of structure being referenced if type is "list".
        scope: scope of the referenced type.
        size: the size (in bits) of the field if the associated type requires
            a size.
        until: holds information about a Parsnip "Until" statement related to
            this field if such information exists. otherwise None.

    Additional class variables:
        inputs: array of Input structures.
            updated using the addInput class function.
    """
    def __init__(self, name, type, referenceType, scope=""):
        """
        Initialization function.

        Args:
            name (str): action name.
            type (str): action type
            referenceType (str): name of the of the referenced structure if
                type is of "bits", "enum", "object", "switch", or "list".
            scope (str, optional): scope containing the reference type.
                defaults to "".
        """
        self.name = name
        self.type = type
        self.referenceType = referenceType
        self.elementType = ""
        self.inputs = []
        self.scope = utils.normalizedScope(scope, type)
        self.size = 0
        self.until = None

    def addInput(self, input):
        """
        Adds an Input structure to the internal list of inputs if it does not
        already exist.

        Args:
            input (inputs.Input): the Input structure to add.
        """
        for existingInput in self.inputs:
            if existingInput.equal(input):
                return
        if input not in self.inputs:
            self.inputs.append(input)

class SwitchOption:
    """
    This class stores data related to a switch option.

    Settable class variables:
        value: the value associated with the option.
        action: the SwitchAction associated with the option.
    """
    def __init__(self, value):
        """
        Initialization function.

        Args:
            value (Any): the value to compare against the Switch dependsOn
            value.
        """
        self.value = value
        self.action = None

class Switch:
    """
    This class stores data related to a Switch structure.

    Settable class variables:
        name: switch structure name.
        dependsOn: the main dependency for the switch. this is the variable
            used to determine which option to take.
        default: optional default option (SwitchOption) for the switch. this
            option is used if no other options are used.
        referenceCount: how many times this switch is referenced by other
            structures.

    Additional class variables:
        additionalDependsOn: additional dependencies for the switch. these
            dependencies typically are forwarded to options that require them.
            updated using the addAdditionalDependsOn class function.
        options: array of SwitchOption structures.
            updated using the addOption class function.
        column: used for formatting text while generating a parser.
            updated using the addOption class function.
        longestOption: used for formatting text. keeps the length of the
            longest option name in options.
            updated using the addOption class function.
        actionColumn: used for formatting text while generating a parser.
            updated using the addOption class function.
        longestAction: used for formatting text while generating a parser.
            keeps the length of the longest action name in options.
            updated using the addOption class function.
    """
    def __init__(self, name, referenceCount):
        """
        Initialization function.

        Args:
            name (str): switch structure name.
            referenceCount (int): how many times this switch is referenced by
                other structures.
        """
        self.name = name
        self.dependsOn = None
        self.additionalDependsOn = []
        self.options = []
        self.default = None
        self.referenceCount = referenceCount
        self.column = 0
        self.longestOption = 0
        self.actionColumn = 0
        self.longestAction = 0

    def addAdditionalDependsOn(self, dependency):
        """
        Adds a (non-duplicate) depedency to this Switch structure instance.

        If the dependency does not current exist as self.dependsOn or in
        self.additionalDependsOn, adds the dependency to the the array of
        dependencies in self.additionalDependsOn.

        Args:
            dependency (inputs.Dependency): the dependency to add to the list
                of additional dependencies.
        """
        for existingDependency in self.additionalDependsOn:
            if existingDependency.equal(dependency):
                return
        if self.dependsOn.equal(dependency):
            return
        self.additionalDependsOn.append(dependency)

    def addOption(self, option):
        """
        Adds a (non-duplicate) option to this Switch structure instance.

        If the option item does not currently exist in self.options, adds the
        option to the array and updates the self.column, self.longestOption,
        self.actionColumn, and self.longestAction values.

        Args:
            option (SwitchOption): the SwitchOption object to add to this
                instance.
        """
        if option not in self.options:
            tempColumn = utils.calculateColumn(len(str(option.value)))
            if tempColumn > self.column:
                self.column = tempColumn
            if len(str(option.value)) > self.longestOption:
                self.longestOption = len(str(option.value))
            tempColumn = utils.calculateColumn(len(option.action.name))
            if tempColumn > self.actionColumn:
                self.actionColumn = tempColumn
            if len(option.action.name) > self.longestAction:
                self.longestAction = len(option.action.name)
            self.options.append(option)
