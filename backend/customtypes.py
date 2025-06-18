# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the CustomType class which is a data storage class for
user-defined types that have a conversion function to convert from bytes to a
built-int type such as string or int.
"""

import utils

class CustomType:
    """
    This class stores data related to user-defined types that the user has
    provided a conversion function for.

    Settable class variables:
        name: The name of the custom type that will be used in the parser.
        interpretingFunction: The name of the function that is or will be
            located in the conversion file for the parser.
        returnType: The built-in return type (e.g., string or uint64) returned
            by the conversion function.
    """
    def __init__(self, name, interpretingFunction, returnType):
        """
        Initialization Function

        Args:
            name (str): The name of the custom type that will be used in the
                parser.
            interpretingFunction (str): The name of the function that is or
                will be located in the conversion file for the parser.
            returnType (str): The built-in return type (e.g., string or uint64)
                returned by the conversion function.
        """
        self.name = name
        self.interpretingFunction = interpretingFunction
        self.returnType = returnType
