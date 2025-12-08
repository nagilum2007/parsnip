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
        source: the source used for the input.
        minus: the amount to subtract from the value of the source or "" for
            none.

    Additional class variables:
        minusInUse: whether or not a minus value is in use.
            updated using the __init__ function.
    """
    def __init__(self, source, minus=""):
        """
        Initialization function.

        Args:
            source (str): a string representing the variable containing the
                value to use for the input.
            minus (str, optional): the amount to subtract from the value used
                for the input or "" for 0. defaults to "".
        """
        self.source = source
        self.minus = minus
        self.minusInUse = True if "" != self.minus else False

    def equal(self, other):
        """
        Checks to see if another Input structure is equal to the current Input
        structure.

        Args:
            other (Input): the Input to compare against.

        Returns:
            bool: True if the inputs are considered equal, otherwise False.
        """
        return self.source == other.source and \
               self.minus == other.minus

    def getString(self):
        """
        Get the string version of the Input structure to use in the parser code.

        Returns:
            str: the string to use in the parser code representing the Input.
        """
        outputString = self.source
        if self.minusInUse:
            outputString += " - " + str(self.minus)
        return outputString

class Dependency:
    """
    This class is used to hold data related to dependencies for an item.

    Settable class variables:
        name: the name of the dependency used locally.
        type: the type of the dpendency.
        size: the size (in bits) of the dependency.
        referenceType: the name of the dependency.
        scope: the scope of the dependency.
    """
    def __init__(self, name, type, size="", referenceType = "", scope = ""):
        """
        Initialization function.

        Args:
            name (str): the name of the dependency used locally.
            type (str): the type of the dependency.
            size (str, optional): the size (in bits) of the dependency.
                defaults to "".
            referenceType (str, optional): the name of the dependency.
                defaults to "".
            scope (str, optional): the scope of the dependency. defaults to "".
        """
        self.name = name
        self.type = type
        self.size = size
        self.referenceType = referenceType
        self.scope = utils.normalizedScope(scope, type)

    def equal(self, other):
        """
        Checks to see if another Dependency structure is equal to the current
        Dependency structure.

        Args:
            other (Dependency): the Dependency structure to compare against.

        Returns:
            bool: True if the inputs are considered equal, otherwise False.
        """
        return self.name == other.name and \
               self.type == other.type and \
               self.size == other.size and \
               self.referenceType == other.referenceType and \
               self.scope == other.scope
