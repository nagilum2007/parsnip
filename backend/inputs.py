# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Input and Dependency classes which represents Required
Inputs and Dependencies for items.
"""

import utils

class Input:
    """
    This class is used to hold data related to inputs for an item.

    Settable class variables:
        source: The source used for the input.
        minus: The amount to subtract from the value of the source or "" for
            none.

    Additional class variables:
        minusInUse: Whether or not a minus value is in use.
            Updated using the __init__ function.
    """
    def __init__(self, source, minus=""):
        """
        Initialization Function

        Args:
            source (str): A string representing the variable containing the
                value to use for the input.
            minus (str, optional): The amount to subtract from the value used
                for the input or "" for 0. Defaults to "".
        """
        self.source = source
        self.minus = minus
        self.minusInUse = True if "" != self.minus else False

    def equal(self, other):
        """
        Checks to see if another Input is equal to the current Input.

        Args:
            other (Input): The Input to compare against.

        Returns:
            bool: True if the inputs are considered equal, otherwise False.
        """
        return self.source == other.source and \
               self.minus == other.minus

    def getString(self):
        """
        Get the string version of the Input to use in the parser code.

        Returns:
            str: The string to use in the parser code representing the Input.
        """
        outputString = self.source
        if self.minusInUse:
            outputString += " - " + str(self.minus)
        return outputString

class Dependency:
    """
    This class is used to hold data related to dependencies for an item.

    Settable class variables:
        name: The name of the dependency used locally.
        type: The type of the dpendency.
        size: The size (in bits) of the dependency.
        referenceType: The name of the dependency.
        scope: The scope of the dependency.
    """
    def __init__(self, name, type, size="", referenceType = "", scope = ""):
        """
        Initialization Function

        Args:
            name (str): The name of the dependency used locally.
            type (str): The type of the dependency.
            size (str, optional): The size (in bits) of the dependency.
                Defaults to "".
            referenceType (str, optional): The name of the dependency.
                Defaults to "".
            scope (str, optional): The scope of the dependency. Defaults to "".
        """
        self.name = name
        self.type = type
        self.size = size
        self.referenceType = referenceType
        self.scope = utils.normalizedScope(scope, type)

    def equal(self, other):
        """
        Checks to see if another Dependency is equal to the current Dependency.

        Args:
            other (Dependency): The Dependency to compare against.

        Returns:
            bool: True if the inputs are considered equal, otherwise False.
        """
        return self.name == other.name and \
               self.type == other.type and \
               self.size == other.size and \
               self.referenceType == other.referenceType and \
               self.scope == other.scope
