# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Bitfield and Bitfield Field classes which are data
storage classes related to Bitfield structures.
"""

import utils
from math import ceil

class BitfieldField:
    """
    This class stores data related to an individual Bitfield Field.

    Settable class variables:
        name: field name.
        description: field description.
        notes: developer notes.
        type: field type (bool, int, enum).
        bits: string representing the bits occupied by the field.
            two formats allowed: "single_bit", "lower_bit..upper_bit".
            example: "3" and "2..7".
        referenceType: enum structure name (if type is of enum).
            used for conversion to a more human-readable value in the parser.
        scope: scope of the reference type.
    """
    def __init__(self, name, description, fieldType, bits, scope = ""):
        """
        Initialization function

        Args:
            name (str): field name
            description (str): field description.
            fieldType (str): field type string.
            bits (str): the bit(s) this field occupies.
                format "bit" or "lower..upper" (i.e., "3" or "2..7").
            scope (str, optional): scope containing the field type.
                defaults to "" (default scope).
        """
        self.name = name
        self.description = description
        self.notes = ""
        self.type = fieldType
        self.bits = bits
        self.referenceType = ""
        self.scope = utils.normalizedScope(scope, fieldType)

class Bitfield:
    """
    This class stores data related to a Bitfield object.

    Settable class variables:
        name: bitfield structure name.
        reference: bitfield structure reference.
                this should be a string providing information of where this
                bitfield structure definition comes from.
                for example, "Specification Unit A, Section 2.5".
        notes: developer notes.
        size: the size of the bitfield structure in bits.
                valid values are 8, 16, 32, and 64.
        scope: scope of the bitfield structure.
        endianness: byte arrangement of the bytes in the bitfield structure.
            valid values are "big" (default) and "little".

    Additional class variables:
        fields: array of BitfieldField structures.
            updated using the addField class function.
        column: used for formatting text while generating a parser.
            updated using the addField class function.
        longestField: used for formatting text.
            keeps the length of the longest field name in fields.
            updated using the addField class function.
    """
    def __init__(self, name, reference, notes, size):
        """
        initialization function

        Args:
            name (str): bitfield structure name.
            reference (str): bitfield structure reference.
                this should be a string providing information of where this
                bitfield structure definition comes from.
                for example, "Specification Unit A, Section 2.5"
            notes (str): user defined notes.
            size (int): the size of the bitfield structure in bits.
                valid values are 8, 16, 32, and 64.
        """
        self.name = name
        self.reference = reference
        self.notes = notes
        self.size = size
        self.fields = []
        self.column = 0
        self.scope = ""
        self.longestField = 0
        self.endianness = "big"

    def addField(self, field):
        """
        Adds a (non-duplicate) BitfieldField structure to this bitfield
        structure instance.

        If the field item does not currently exist in self.fields, adds the
        field to the array and updates the self.column and self.longestField
        values.

        Args:
            field (BitfieldField): BitfieldField structure to add to this instance.
        """
        for existingField in self.fields:
            if existingField.name == field.name:
                return
        if (ceil((len(field.name) + 1)/4) * 4) > self.column:
            self.column = (ceil((len(field.name) + 1)/4) * 4)
        if (len(field.name) > self.longestField):
            self.longestField = len(field.name)
        self.fields.append(field)
