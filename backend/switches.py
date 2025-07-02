# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Switch and related classes which are data storage
classes related to Switch objects.
"""

import utils

class SwitchAction:
    """
    This class stores data related to a switch action.

    Settable class variables:
        name: Action name.
        type: Action type
        referenceType: Name of the of the referenced structure if type is of
            "bits", "enum", "object", "switch", or "list".
        elementType: The type of structure being referenced if type is "list".
        scope: Scope of the referenced type.
        size: The size (in bits) of the field if the associated type requires
            a size.
        until: Holds information about a Parsnip "Until" statement related to
            this field if such information exists. Otherwise None.

    Additional class variables:
        inputs: Array of Input objects.
            Updated using the addInput class function.
    """
    def __init__(self, name, type, referenceType, scope=""):
        """
        Initialization Function

        Args:
            name (str): Action name.
            type (str): Action type
            referenceType (str): Name of the of the referenced structure if
                type is of "bits", "enum", "object", "switch", or "list".
            scope (str, optional): Scope containing the reference type.
                Defaults to "".
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
        Adds an Input object to the internal list of inputs if it does not
        already exist.

        Args:
            input (inputs.Input): The Input object to add.
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
        value: The value associated with the option.
        action: The SwitchAction associated with the option.
    """
    def __init__(self, value):
        """
        Initialization Function

        Args:
            value (Any): The value to compare against the Switch dependsOn
            value.
        """
        self.value = value
        self.action = None

class Switch:
    """
    This class stores data related to a Switch object.

    Settable class variables:
        name: Switch object name.
        dependsOn: The main dependency for the switch. This is the variable
            used to determine which option to take.
        default: Optional default option (SwitchOption) for the switch. This
            option is used if no other options are used.
        referenceCount: How many times this switch is referenced by other
            structures.

    Additional class variables:
        additionalDependsOn: Additional dependencies for the switch. These
            dependencies typically are forwarded to options that require them.
            Updated using the addAdditionalDependsOn class function.
        options: Array of SwitchOption objects.
            Updated using the addOption class function.
        column: Used for formatting text while generating a parser.
            Updated using the addOption class function.
        longestOption: Used for formatting text. Keeps the length of the
            longest option name in options.
            Updated using the addOption class function.
        actionColumn: Used for formatting text while generating a parser.
            Updated using the addOption class function.
        longestAction: Used for formatting text while generating a parser.
            Keeps the length of the longest action name in options.
            Updated using the addOption class function.
    """
    def __init__(self, name, referenceCount):
        """
        Initialization Function

        Args:
            name (str): Switch object name.
            referenceCount (int): How many times this switch is referenced by
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
        Adds a (non-duplicate) depedency to this Switch object instance.

        If the dependency does not current exist as self.dependsOn or in
        self.additionalDependsOn, adds the dependency to the the array of
        dependencies in self.additionalDependsOn.

        Args:
            dependency (inputs.Dependency): The dependency to add to the list
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
        Adds a (non-duplicate) option to this Switch object instance.

        If the option item does not currently exist in self.options, adds the
        option to the array and updates the self.column, self.longestOption,
        self.actionColumn, and self.longestAction values.

        Args:
            option (SwitchOption): The SwitchOption object to add to this
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
