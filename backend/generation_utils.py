# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds general parser generation utility functions.
"""

import utils
import graphing
import json
import os
from string import Template

# Graph Theory Imports
import rustworkx as rx

def copyFile(source, destination):
    """
    Copies a (non-template) file from one location to another.

    Args:
        source (str): Path to the source file.
        destination (str): Path to copy the file specified by source to.
    """
    with open(source, "r") as inputFile, open(destination, "w") as currentFile:
        currentFile.write(inputFile.read())

def copyTemplateFile(source, data, destination):
    """
    Copies a template file from one location to another while loading data
    into the template.

    Args:
        source (str): Path to the source template file.
        data (dict): Dictionary of data to fill into the template.
        destination (str): Path to save the output file to.
    """
    with open(source, "r") as inputFile, open(destination, "w") as currentFile:
        currentFile.write(Template(inputFile.read()).substitute(data))

def writeNodes(nodes, outFilePath):
    """
    Saves graph node information to an output file. A string representation of
    the graph node will be saved. Each line of the file represents a node.

    Args:
        nodes (list): Graph node information to save.
        outFilePath (str): Path to save the node information to.
    """
    with open(outFilePath, "w") as outFile:
            for node in nodes:
                outFile.write(node + "\n")

def writeDataToFile(data, outFilePath):
    """
    Saves a preformatted string to an output file.

    Args:
        data (str): Data string to save.
        outFilePath (str): Path to save the data to.
    """
    with open(outFilePath, "w") as outFile:
        outFile.write(data)

def createAndUseGraphInformation(configuration, objects, switches, bitfields, enums, entryPointScope, entryPointName, entryPointKey):
    """
    Generates a mathematical graph representing the parser and then updates
    parts of the parser using that information.

    Args:
        configuration (Config): Parser configuration information.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.
        entryPointKey (str): The name of the graph node for the entry point
            Object.
    """
    ############################################################################
    # Load the structures as nodes
    ############################################################################
    graph, objectNodes, nodeInformation, nodeToIndex, indexToNode, connectionData = generateGraph(configuration, objects, switches, bitfields, enums)

    ############################################################################
    # Create actual graph
    ############################################################################

    # Determine paths for every node from the EntryPoint Node
    pathInformation = calculatePathInformation(graph, objectNodes, entryPointScope, entryPointKey, nodeInformation, nodeToIndex, indexToNode)

    # Look for cycles in the graph
    cycleIndices = rx.simple_cycles(graph)
    cycles = []
    for cycle in cycleIndices:
        mappedCycle = []
        for index in cycle:
            mappedCycle.append(indexToNode[index])
        cycles.append(mappedCycle)

    missingExpectedTopLevelNodes, expectedTopLevelNodes, unexpectedTopLevelNodes = determineTopLevelNodes(graph, [entryPointKey], indexToNode)

    ############################################################################
    # Use the graph information
    ############################################################################
    printGraphWarnings(cycles, missingExpectedTopLevelNodes, unexpectedTopLevelNodes)
    ############################################################################
    # This line outputs calculated graphing information to files.
    # This takes a while so should only be run for debugging.
    ############################################################################
    #saveGraphInformation(graph, pathInformation, cycles, missingExpectedTopLevelNodes, unexpectedTopLevelNodes)

    updateObjectsBasedOnGraphInformation(cycles, pathInformation, objects, entryPointScope, entryPointName)

def generateProtocolEvents(normalScope, entryPointScope, entryPointName, trasportProtos, usesLayer2=False):
    """
    Generates the event string needed to have the parser called for the
    protocols it works with.

    Args:
        normalScope (str): Normalized scope of the entry point Object.
        entryPointScope (str): Non-normalized scope of the entry point Object.
        entryPointName (str): Name of the entry point Object.
        trasportProtos (list): List of transport protocols (from
            {"tcp", "udp"}) that the parser works over.
        usesLayer2 (bool, optional): Whether or not the parser works over
            Layer 2 instead of TCP or UDP. Defaults to False.

    Returns:
        str: The event string needed to have the parser called for the
            protocols it works with.
    """
    # TODO: Do we need to use the entryPointScope value anywhere here?
    eventString = ""
    for protocol in trasportProtos:
        eventString += "protocol analyzer spicy::{}_{} over {}:\n".format(utils.PROTOCOL_NAME.upper(), protocol, protocol)
        eventString += "{}parse with {}::{}".format(utils.SINGLE_TAB, normalScope, entryPointName + "s")
        eventString += ";\n\n"
    if usesLayer2:
        eventString += "packet analyzer spicy::{}:\n".format(utils.PROTOCOL_NAME.upper())
        eventString += "{}parse with {}::{};".format(utils.SINGLE_TAB, normalScope, entryPointName + "s")
        eventString += "\n\n"
    return eventString

def _addCrossScopeItem(currentScope, otherScope, itemType, itemReference, crossScopeList):
    """
    Adds information scopes that have interdependencies. This information is
    used for generating imports.

    Args:
        currentScope (str): The scope that references an item in a different
            scope.
        otherScope (str): The scope containing the item that is referenced.
        itemType (str): The type of item that is referenced.
        itemReference (str): The name of the item that is referenced.
        crossScopeList (dict): The dictionary to save the reference
            information to.
    """
    if currentScope not in crossScopeList:
        crossScopeList[currentScope] = {}
    if otherScope not in crossScopeList[currentScope]:
        crossScopeList[currentScope][otherScope] = {}
    if itemType not in crossScopeList[currentScope][otherScope]:
        crossScopeList[currentScope][otherScope][itemType] = set()
    crossScopeList[currentScope][otherScope][itemType].add(itemReference)

def processDependency(item, currentScope, crossScopeList, customTypes, switches, bitfields):
    """
    Processes a dependency item and updates any references necessary.

    Args:
        item (object representing a field, option, or dependency): An item
            (Object Field, Object Dependency, Bitfield Field, or Switch
            Option) which is referenced by another item.
        currentScope (str): The scope of the item referencing the item passed
            in.
        crossScopeList (dict): The dictionary to save any necessary reference
            information to.
        customTypes (dict): The dictionary of any custom types used by the
            parser.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
    """
    if item.type in ["enum", "object"]:
        if item.scope != currentScope:
            # Crossing the scopes
            _addCrossScopeItem(currentScope, item.scope, item.type, item.referenceType, crossScopeList)
    elif item.type in ["bits"]:
        for field in bitfields[item.scope][item.referenceType].fields:
            if field.scope != currentScope:
                _addCrossScopeItem(currentScope, field.scope, field.type, field.referenceType, crossScopeList)
    elif item.type in ["list"] and item.elementType in ["enum", "object"]:
        if item.scope != currentScope:
            # Crossing the scopes
            _addCrossScopeItem(currentScope, item.scope, item.elementType, item.referenceType, crossScopeList)
    elif item.type in ["switch"] and \
         item.scope in switches and \
         item.referenceType in switches[item.scope]:
        for option in switches[item.scope][item.referenceType].options:
            processDependency(option.action, currentScope, crossScopeList, customTypes, switches, bitfields)
    elif item.type in customTypes:
        normalConversionScope = utils.normalizedScope(utils.CONVERSION_SCOPE, "custom")
        _addCrossScopeItem(currentScope, normalConversionScope, "custom", item.type, crossScopeList)

def _addUserTypeNodes(configuration, nodeInformation):
    """
    Adds graph nodes for custom types used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
    """
    if bool(configuration.customFieldTypes):
        for name in configuration.customFieldTypes:
            item = configuration.customFieldTypes[name]
            metaData = {
                "interpretingFunction": item.interpretingFunction,
                "returnType": item.returnType
            }
            graphing.addUserTypeNode(name, nodeInformation, metaData, configuration.customFieldTypes.keys())

def _addObjectNodes(configuration, objects, nodeInformation, objectNodes, referenceInformation, fieldsInformation):
    """
    Adds graph nodes for Objects used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        objectNodes (dict): Object Node information dictionary to save the
            graph nodes to.
        referenceInformation (list): Connection information of connections due
            to types referenced by the objects.
        fieldsInformation (list): Connection information of connections due to
            Object fields.
    """
    for normalizedScope in objects:
        for objectName in objects[normalizedScope]:
            currentObject = objects[normalizedScope][objectName]
            itemName = graphing.addItemNode(normalizedScope, currentObject,
                                   "object", nodeInformation, None,
                                   configuration.customFieldTypes.keys())
            objectNodes.append(graphing.normalizedKey3(normalizedScope, "object", itemName))

            # Process the fields
            for field in currentObject.fields:
                graphing.addFieldNode(normalizedScope, "object", itemName,
                                      field, "field", nodeInformation,
                                      referenceInformation, fieldsInformation,
                                      configuration.customFieldTypes.keys())

def _addObjectDependencyNodes(configuration, objects, dependencyNodeInformation, dependencyReferenceInformation, dependencyInformation):
    """
    Adds graph nodes for dependencies for Object nodes.

    Args:
        configuration (Config): Parser configuration information.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        dependencyNodeInformation (dict): Graph node dictionary to save
            dependency nodes to.
        dependencyReferenceInformation (list): Connection information of
            connections related to the dependency nodes.
        dependencyInformation (list): Connection information of connections
            related to dependency fields.
    """
    for normalizedScope in objects:
        for objectName in objects[normalizedScope]:
            currentObject = objects[normalizedScope][objectName]
            itemName = graphing.getItemName(normalizedScope, currentObject, "object")

            # Look for references in the dependsOn section
            if len(currentObject.dependsOn) > 0:
                for dependency in currentObject.dependsOn:
                    graphing.addDependencyNode(normalizedScope, "object",
                                               itemName, dependency,
                                               dependencyNodeInformation,
                                               dependencyReferenceInformation,
                                               dependencyInformation,
                                               configuration.customFieldTypes.keys())

def _addSwitchNodes(configuration, switches, nodeInformation, referenceInformation, fieldsInformation):
    """
    Add graph nodes for Switches used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        referenceInformation (list): Connection information of connections due
            to types referenced by the switches.
        fieldsInformation (list): Connection information of connections due to
            Switch options.
    """
    for normalizedScope in switches:
        for switchName in switches[normalizedScope]:
            currentSwitch = switches[normalizedScope][switchName]
            itemName = graphing.addItemNode(normalizedScope, currentSwitch,
                                            "switch", nodeInformation, None,
                                            configuration.customFieldTypes.keys())

            # Process the "fields"
            for option in currentSwitch.options:
                actionSection = option.action
                graphing.addFieldNode(normalizedScope, "switch", itemName,
                                      actionSection, "option", nodeInformation,
                                      referenceInformation, fieldsInformation,
                                      configuration.customFieldTypes.keys())
            if currentSwitch.default is not None:
                action = currentSwitch.default
                graphing.addFieldNode(normalizedScope, "switch", itemName,
                                      action, "option", nodeInformation,
                                      referenceInformation, fieldsInformation,
                                      configuration.customFieldTypes.keys())

def _addSwitchDependencyNodes(configuration, switches, dependencyNodeInformation, dependencyReferenceInformation, dependencyInformation):
    """
    Adds graph nodes for dependencies for Switch nodes.

    Args:
        configuration (Config): Parser configuration information.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        dependencyNodeInformation (dict): Graph node dictionary to save
            dependency nodes to.
        dependencyReferenceInformation (list): Connection information of
            connections related to the dependency nodes.
        dependencyInformation (list): Connection information of connections
            related to dependency fields.
    """
    for normalizedScope in switches:
        for switchName in switches[normalizedScope]:
            currentSwitch = switches[normalizedScope][switchName]
            itemName = graphing.getItemName(normalizedScope, currentSwitch, "switch")
            # Process the main dependency
            dependsOnSection = currentSwitch.dependsOn
            graphing.addDependencyNode(normalizedScope, "switch", itemName,
                                       dependsOnSection,
                                       dependencyNodeInformation,
                                       dependencyReferenceInformation,
                                       dependencyInformation,
                                       configuration.customFieldTypes.keys())
            # Look for references in the additionalDependsOn section
            if len(currentSwitch.additionalDependsOn) > 0:
                for dependency in currentSwitch.additionalDependsOn:
                    graphing.addDependencyNode(normalizedScope, "switch",
                                               itemName, dependency,
                                               dependencyNodeInformation,
                                               dependencyReferenceInformation,
                                               dependencyInformation,
                                               configuration.customFieldTypes.keys())

def _addBitfieldNodes(configuration, bitfields, nodeInformation, referenceInformation, fieldsInformation):
    """
    Add graph nodes for Bitfields used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        referenceInformation (list): Connection information of connections due
            to types referenced by the bitfields.
        fieldsInformation (list): Connection information of connections due to
            Bitfield fields.
    """
    for normalizedScope in bitfields:
        for bitfieldName in bitfields[normalizedScope]:
            currentBitfield = bitfields[normalizedScope][bitfieldName]
            itemName = graphing.addItemNode(normalizedScope, currentBitfield,
                                            "bits", nodeInformation, None,
                                            configuration.customFieldTypes.keys())
            # No dependencies
            # Process the fields
            for field in currentBitfield.fields:
                graphing.addFieldNode(normalizedScope, "bits", itemName, field,
                                      "field", nodeInformation,
                                      referenceInformation, fieldsInformation,
                                      configuration.customFieldTypes.keys())

def _addEnumNodes(configuration, enums, nodeInformation, referenceInformation, fieldsInformation):
    """
    Add graph nodes for Enums used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        referenceInformation (list): Connection information of connections due
            to types referenced by the enums.
        fieldsInformation (list): Connection information of connections due to
            Enum fields.
    """
    for normalizedScope in enums:
        for enumName in enums[normalizedScope]:
            currentEnum = enums[normalizedScope][enumName]
            itemName = graphing.addItemNode(normalizedScope, currentEnum,
                                            "enum", nodeInformation, None,
                                            configuration.customFieldTypes.keys())
            # No dependencies
            # Process the fields
            for field in currentEnum.fields:
                graphing.addFieldNode(normalizedScope, "enum", itemName, field,
                                      "field", nodeInformation,
                                      referenceInformation, fieldsInformation,
                                      configuration.customFieldTypes.keys())

def _addNodes(configuration, objects, switches, bitfields, enums):
    """
    Adds the various types of nodes for the graph and returns the information.

    Args:
        configuration (Config): Parser configuration information.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        (list, dict, list, list): A tuple with the following values:
            1. List of Object graph nodes.
            2. Node information where the keys are the names of the nodes.
            3. List of connection information from fields and options.
            4. List of connection information from references.
    """
    ################################################################################
    # Tracking Structures
    ################################################################################
    # Assumption, no duplicates

    # Nodes
    nodeInformation = {}
    objectNodes = []
    # Connections due to type references
    referenceInformation = []
    # Connections due to fields
    fieldsInformation = []

    _addUserTypeNodes(configuration, nodeInformation)

    _addObjectNodes(configuration, objects, nodeInformation, objectNodes, referenceInformation, fieldsInformation)

    _addSwitchNodes(configuration, switches, nodeInformation, referenceInformation, fieldsInformation)

    _addBitfieldNodes(configuration, bitfields, nodeInformation, referenceInformation, fieldsInformation)

    _addEnumNodes(configuration, enums, nodeInformation, referenceInformation, fieldsInformation)

    # Dependency Information
    # Not currently used, so removing for now
    #dependencyNodeInformation = {}
    #dependencyReferenceInformation = []
    # Connections due to other dependencies
    #dependencyInformation = []

    #_addObjectDependencyNodes(configuration, objects, dependencyNodeInformation, dependencyReferenceInformation, dependencyInformation)
    #_addSwitchDependencyNodes(configuration, switches, dependencyNodeInformation, dependencyReferenceInformation, dependencyInformation)

    return (objectNodes, nodeInformation, fieldsInformation, referenceInformation)

def generateGraph(configuration, objects, switches, bitfields, enums):
    """
    Generates the graph information used to manipulate the parser input.

    Args:
        configuration (Config): Parser configuration information.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        (rustworkx.PyDiGraph, list, dict, dict, dict, dict): A tuple with the
            following values:
            1. Rustworkx graph representing the parser.
            2. List of Object graph nodes.
            3. Node information where the keys are the names of the nodes.
            4. Map of node names to node index number.
            5. Map of node index number to node names.
            6. Connection information where the keys are the connection ID.
    """
    ############################################################################
    # Load the structures as nodes
    ############################################################################
    objectNodes, nodeInformation, fieldsInformation, referenceInformation = \
        _addNodes(configuration, objects, switches, bitfields, enums)

    ############################################################################
    # Create actual graph
    ############################################################################
    graph = rx.PyDiGraph(multigraph=False)
    nodeToIndex = {}
    indexToNode = {}
    connectionData = {}

    for node in nodeInformation:
        if node not in nodeToIndex:
            nodeIndex = graph.add_node(node)
            nodeToIndex[node] = nodeIndex
            indexToNode[nodeIndex] = node


    for connection in fieldsInformation:
        connectionID = graph.add_edge(nodeToIndex[connection[0]], nodeToIndex[connection[1]], None)
        connectionData[connectionID] = connection[2]

    for connection in referenceInformation:
        connectionID = graph.add_edge(nodeToIndex[connection[0]], nodeToIndex[connection[1]], None)
        connectionData[connectionID] = connection[2]

    return (graph, objectNodes, nodeInformation, nodeToIndex, indexToNode, connectionData)

def _processPath(path, entryPointScope, targetScope, nodeInformation, indexToNode):
    """
    Processes a path in the graph and returns metadata related to that path.
    The path should have the last element be the node that we are currently
    trying to gain information about.
    The returned metadata includes:
        - path: (list) The path of nodes that was processed.
        - needsLoggingParent: (bool) True if a specific logging parent is
            needed.
        - loggingParent: (str) The logging parent to use
            (defaults to the entry point scope).
        - reason: (str, optional) The reason the logging parent is needed
            (if one is).

    Args:
        path (list): Graph node path to process.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        targetScope (str): The scope of the node we want the metadata for.
        nodeInformation (dict): Node information where the keys are the names
            of the nodes.
        indexToNode (dict): Map of node index number to node names.

    Returns:
        dict: Dictionary of metadata about the path. The returned metadata
            includes:
            - path: (list) The path of nodes that was processed.
            - needsLoggingParent: (bool) True if a specific logging parent is
                needed.
            - loggingParent: (str) The logging parent to use
                (defaults to the entry point scope).
            - reason: (str, optional) The reason the logging parent is needed
                (if one is).
    """
    tempPath = []
    for element in path:
        tempPath.append(indexToNode[element])
    loggingParent = None
    parentReason = ""
    previousScope = None
    pathInfo = {}
    for element in tempPath[::-1]:
        parts = element.split(".")
        if len(parts) < 3:
            continue
        scope = parts[0]
        referenceType = parts[2]
        if scope != targetScope:
            loggingParent = utils.loggingParentScope(previousScope)
            parentReason = "Scope Change"
            break
        metaData = nodeInformation[element][1]
        if metaData is not None:
            if "logIndependently" in metaData and True == metaData["logIndependently"]:
                loggingParent = referenceType
                parentReason = "Log Independently"
                break
        previousScope = scope
    pathInfo["path"] = tempPath
    if loggingParent is None:
        pathInfo["needsLoggingParent"] = False
        pathInfo["loggingParent"] = utils.loggingParentScope(entryPointScope)
    else:
        pathInfo["needsLoggingParent"] = True
        pathInfo["loggingParent"] = loggingParent
        pathInfo["reason"] = parentReason

    return pathInfo

def calculatePathInformation(graph, objectNodes, entryPointScope, entryPointKey, nodeInformation, nodeToIndex, indexToNode):
    """
    Generates path information for all paths in a parser graph.

    Args:
        graph (rustworkx.PyDiGraph): Rustworkx graph representing the parser.
        objectNodes (list): List of Object graph nodes.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointKey (str): The name of the graph node for the entry point
            Object.
        nodeInformation (dict): Node information where the keys are the names
            of the nodes.
        nodeToIndex (dict): Map of node names to node index number.
        indexToNode (dict): Map of node index number to node names.

    Returns:
        dict: Dictionary where the key is the scope and Object name
            (in the form scope::name) and the value is a list of path
            information (metadata) for every path to that object. The path
            information is a dictionary which includes includes:
            - path: (list) The path of nodes that was processed.
            - needsLoggingParent: (bool) True if a specific logging parent is
                needed.
            - loggingParent: (str) The logging parent to use
                (defaults to the entry point scope).
            - reason: (str, optional) The reason the logging parent is needed
                (if one is).
    """
    # Determine paths for every node from the EntryPoint Node
    pathInformation = {}
    for node in objectNodes:
        if node == entryPointKey:
            continue
        paths = []
        targetParts = node.split(".")
        if len(targetParts) < 3:
            print("Bad Path Value '{0}'".format(node))
            continue
        targetScope = targetParts[0]
        #targetType = targetParts[1]
        targetName = targetParts[2]
        for path in rx.all_simple_paths(graph, nodeToIndex[entryPointKey], nodeToIndex[node]):
            paths.append(_processPath(path, entryPointScope, targetScope, nodeInformation, indexToNode))
        pathInformation["{0}::{1}".format(targetScope, targetName)] = paths
    return pathInformation

def determineTopLevelNodes(graph, expectedTopLevelNodes, indexToNode):
    """
    Determine all top-level nodes in the graph. Top-level nodes are nodes
    which are nodes that are not referenced by other nodes. In theory, the
    only top-level node that should occur should be the one for the entry
    point node. Often in partial parser definitions, other top level will
    exist for items that exist, but have not be used.

    Args:
        graph (rustworkx.PyDiGraph): Rustworkx graph representing the parser.
        expectedTopLevelNodes (list): A list of expected top level nodes.
            Normally, this should consist of just the entry point node.
        indexToNode (dict): Map of node index number to node names.

    Returns:
        (list, list, list): A tuple with the following values:
            1. A list of missing expected top-level nodes.
            2. A list of found expected top-level nodes.
            3. A list of unexpected top-level nodes.
    """
    unexpectedNodes = []
    expectedNodes = []
    missingNodes = []
    for node in graph.node_indices():
        if graph.in_degree(node) == 0:
            if indexToNode[node] in expectedTopLevelNodes:
                expectedNodes.append(indexToNode[node])
            else:
                unexpectedNodes.append(indexToNode[node])
    for node in expectedTopLevelNodes:
        if node not in expectedNodes:
            missingNodes.append(node)
    return (missingNodes, expectedNodes, unexpectedNodes)

def printGraphWarnings(cycles, missingTopLevelNodes, unexpectedTopLevelNodes):
    """
    Prints warnings about issues found with the graph to stdout.

    Args:
        cycles (list): A list of cycles found in the graph. Each item in the
            list is a list of all nodes involved in the cycle.
        missingTopLevelNodes (list): A list of expected top-level nodes that
            were not found in the graph.
        unexpectedTopLevelNodes (list): A list of unexpected top-level nodes
            that were found in the graph.
    """
    if len(cycles) > 0:
         print()
         print("Warning: {} Cycles Found".format(len(cycles)))
         print()

         # Iterate over all cycles
         #for cycle in cycles:
         #    # Iterate over nodes within a cycle
         #    # First node is the node closest to the "Entry Point" node that we specify
         #    # Last node is the node that references the first node in the cycle
         #    # and creates the loop
         #    cycleStart = cycle[0]
         #    cycleEnd = cycle[-1]
         #    print("Cycle Start: {}, Cycle End: {}".format(cycleStart, cycleEnd))
         #    cycleString = ""
         #    for index, node in enumerate(cycle):
         #        cycleString = cycleString + node
         #        if index < len(cycle) - 1:
         #            cycleString += " -> "
         #    print(cycleString)

    if 0 != len(missingTopLevelNodes):
        print()
        print("Warning: {} Expected Top Level Nodes were Missing".format(len(missingTopLevelNodes)))
        print()

    if 0 != len(unexpectedTopLevelNodes):
        print()
        print("Warning: {} Unexpected Top Level Nodes Found".format(len(unexpectedTopLevelNodes)))
        print()

def saveGraphInformation(graph, pathInformation, cycles, missingExpectedTopLevelNodes, unexpectedTopLevelNodes):
    """
    Saves information about the graph to various files.
    Output Files:
        - paths.json: Path information for the graph.
        - cycles.txt: Cycles found in the graph. Each line consists of one
            cycle.
        - missing_expected_nodes.txt: Expected top-level nodes that were not
            found in the graph. Each line consists of one such node.
        - unexpected_top_nodes.txt: Unexpected top-level nodes that were found
            in the graph. Each line consists of one such node.
        - output_no_dependencies.svg: Currently, this one is not being
            generated, but was in the past. This is an SVG image
            representation of the graph without dependency information
            included.

    Args:
        graph (rustworkx.PyDiGraph): Rustworkx graph representing the parser.
        pathInformation (dict): Dictionary where the key is the scope and
            Object name (in the form scope::name) and the value is a list of
            path information (metadata) for every path to that object. The
            path information is a dictionary which includes includes:
                - path: (list) The path of nodes that was processed.
                - needsLoggingParent: (bool) True if a specific logging parent
                    is needed.
                - loggingParent: (str) The logging parent to use
                    (defaults to the entry point scope).
                - reason: (str, optional) The reason the logging parent is
                    needed (if one is).
        cycles (list): A list of cycles found in the graph. Each item in the
            list is a list of all nodes involved in the cycle.
        missingExpectedTopLevelNodes (list): A list of expected top-level
            nodes that were not found in the graph.
        unexpectedTopLevelNodes (list): A list of unexpected top-level nodes
            that were found in the graph.
    """
    writeDataToFile(json.dumps(pathInformation, indent=4), "paths.json")

    if len(cycles) > 0:
        cycleString = ""
        for cycle in cycles:
            for index, node in enumerate(cycle):
                cycleString = cycleString + node
                if index < len(cycle) - 1:
                    cycleString += " -> "
            cycleString += "\n"
        writeDataToFile(cycleString, "cycles.txt");
    if 0 != len(missingExpectedTopLevelNodes):
        writeNodes(missingExpectedTopLevelNodes, "missing_expected_nodes.txt")

    if 0 != len(unexpectedTopLevelNodes):
        writeNodes(unexpectedTopLevelNodes, "unexpected_top_nodes.txt")

    # TODO: Update these to work with rustworkx
    #dotGraph = nx.nx_pydot.to_pydot(graph)
    #dotGraph.write_svg("output_no_dependencies.svg")

def updateObjectsBasedOnGraphInformation(cycles, pathInformation, objects, entryPointScope, entryPointName):
    """
    Actually update the parser based on information gained from building a
    graph of it.

    Args:
        cycles (list): A list of cycles found in the graph. Each item in the
            list is a list of all nodes involved in the cycle.
        pathInformation (dict): Dictionary where the key is the scope and
            Object name (in the form scope::name) and the value is a list of
            path information (metadata) for every path to that object. The
            path information is a dictionary which includes includes:
                - path: (list) The path of nodes that was processed.
                - needsLoggingParent: (bool) True if a specific logging parent
                    is needed.
                - loggingParent: (str) The logging parent to use
                    (defaults to the entry point scope).
                - reason: (str, optional) The reason the logging parent is
                    needed (if one is).
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        entryPointScope (str): Non-normalized scope of the entry point Object.
        entryPointName (str): Name of the entry point Object.
    """
    # Deal with cycles
    for cycle in cycles:
        takenCareOf = False
        for item in cycle:
            cycleParts = item.split(".")
            if "object" == cycleParts[1]:
                try:
                    objects[cycleParts[0]][cycleParts[2]].needsSpecificExport = True
                    takenCareOf = True
                    break
                except KeyError:
                    print("Unknown cycle object: {}".format(item))
        if not takenCareOf:
            print("Unable to process cycl")

    for normalizedScope in objects:
        for objectName in objects[normalizedScope]:
            if objectName == entryPointName:
                objects[normalizedScope][objectName].zeekStructure.append(entryPointScope)
                continue
            for path in pathInformation["{}::{}".format(normalizedScope,objectName)]:
                if "loggingParent" in path:
                    objects[normalizedScope][objectName].zeekStructure.append(path["loggingParent"])

def determineInterScopeDependencies(configuration, bitfields, objects, switches):
    """
    Determines any inter-scope dependencies that exist.

    Args:
        configuration (Config): Parser configuration information.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.

    Returns:
        dict: A dictionary containing information about cross-scope
            dependencies. The key represents the scope that has dependencies.
            The value is dictionary with keys representing the scopes where
            the dependencies reside. The values are dictionaries where the
            keys are a subset of "enum", "object", "custom", and "id". The
            values of these dictionaries are sets with the actual dependency
            names.
    """
    # Determine import requirements
    # currentScope -> dependentScope[] -> ["enum"/"object"/"custom"/"id"] -> referenceType[]
    crossScopeItems = {}
    for scope in configuration.scopes:
        normalScope = utils.normalizedScope(scope, "")
        if normalScope in objects:
            print("Processing objects in scope: {0}".format(normalScope))
            for currentObjectName in objects[normalScope]:
                currentObject = objects[normalScope][currentObjectName]
                if currentObject.linkIds != []:
                    for link in currentObject.linkIds:
                        if not link.isEndLink:
                            normalIDScope = utils.normalizedScope(utils.ID_SCOPE, "")
                            if normalScope not in crossScopeItems:
                                crossScopeItems[normalScope] = {}
                            if normalIDScope not in crossScopeItems[normalScope]:
                                crossScopeItems[normalScope][normalIDScope] = {}
                            if "id" not in crossScopeItems[normalScope][normalIDScope]:
                                crossScopeItems[normalScope][normalIDScope]["id"] = set()
                for dependency in currentObject.dependsOn:
                    processDependency(dependency, normalScope, crossScopeItems, configuration.customFieldTypes, switches, bitfields)
                for field in currentObject.fields:
                    processDependency(field, normalScope, crossScopeItems, configuration.customFieldTypes, switches, bitfields)
                for link in currentObject.linkIds:
                    if not link.isEndLink:
                        normalConversionScope = utils.normalizedScope(utils.CONVERSION_SCOPE, "custom")
                        if normalScope not in crossScopeItems:
                                crossScopeItems[normalScope] = {}
                        if normalConversionScope not in crossScopeItems[normalScope]:
                            crossScopeItems[normalScope][normalConversionScope] = {}
                        if "custom" not in crossScopeItems[normalScope][normalConversionScope]:
                            crossScopeItems[normalScope][normalConversionScope]["custom"] = set()
                #if  currentObject.needsSpecificExport and currentObject.logWithParent:
                    #for path in pathInformation["{}::{}".format(utils.normalizedScope(scope, "object"),currentObject.name)]:
                        #print(path)
        if normalScope in switches:
            print("Processing switches in scope: {0}".format(normalScope))
            for currentSwitchName in switches[normalScope]:
                currentSwitch = switches[normalScope][currentSwitchName]
                for option in currentSwitch.options:
                    processDependency(option.action, normalScope, crossScopeItems, configuration.customFieldTypes, switches, bitfields)
        if normalScope in bitfields:
            print("Processing bitfields in scope: {0}".format(normalScope))
            for currentBitfieldName in bitfields[normalScope]:
                currentBitfield = bitfields[normalScope][currentBitfieldName]
                for field in currentBitfield.fields:
                    processDependency(field, normalScope, crossScopeItems, configuration.customFieldTypes, switches, bitfields)
    return crossScopeItems

def writeBasicFiles(configuration, outRootFolder):
    """
    Generate and output basic files for the parser. These files include:
    - .gitignore
    - README.md

    Args:
        configuration (Config): Parser configuration information.
        outRootFolder (str): Output folder path.
    """
    # .gitignore
    if configuration.gitignoreFile is not None:
        writeDataToFile(configuration.gitignoreFile,
                        os.path.join(outRootFolder, ".gitignore"))
    else:
        copyFile(os.path.join("templates", "gitignore.in"),
                 os.path.join(outRootFolder, ".gitignore"))

    # README
    data = {
        "protocolName": utils.PROTOCOL_NAME,
        "protocolDescription": configuration.longDescription,
        "outputFolder": os.path.basename(os.path.normpath(outRootFolder))
    }

    copyTemplateFile(os.path.join("templates", "README.md.in"), data,
                     os.path.join(outRootFolder, "README.md"))

def writeCMakeFiles(outRootFolder):
    """
    Generate and output the CMakeLists.txt and
    cmake/FindSpicyPlugin.cmake files for the parser.

    Args:
        outRootFolder (str): Output root folder path.
    """
    # Create root CMakeLists.txt file
    data = {"protocol": utils.PROTOCOL_NAME}
    copyTemplateFile(os.path.join("templates", "root_CMakeLists.txt.in"),
                     data,
                     os.path.join(outRootFolder, "CMakeLists.txt"))

    # Create cmake folder contents
    cmakeFolder = os.path.join(outRootFolder, "cmake")
    os.makedirs(cmakeFolder, exist_ok=True)

    copyFile(os.path.join("templates", "FindSpicyPlugin.cmake.in"),
             os.path.join(cmakeFolder, "FindSpicyPlugin.cmake"))

def writeTestFiles(outRootFolder):
    """
    Generate and output btests-related files for the parser. This creates the
    following folders and files:
    - testing/
    - testing/btest.cfg
    - testing/tests/
    - testing/tests/availability.zeek
    - testing/scripts/
    - testing/scripts/diff-remove-timestamps
    - testing/scripts/get-zeek-env
    - testing/files/
    - testing/files/random.seed
    - testing/traces/

    Args:
        outRootFolder (str): Output root folder path.
    """
    # Create test folder contents
    testingFolder = os.path.join(outRootFolder, "testing")
    os.makedirs(testingFolder, exist_ok=True)
    testsFolder = os.path.join(testingFolder, "tests")
    os.makedirs(testsFolder, exist_ok=True)
    scriptsFolder = os.path.join(testingFolder, "scripts")
    os.makedirs(scriptsFolder, exist_ok=True)
    filesFolder = os.path.join(testingFolder, "files")
    os.makedirs(filesFolder, exist_ok=True)
    tracesFolder = os.path.join(testingFolder, "traces")
    os.makedirs(tracesFolder, exist_ok=True)

    copyFile(os.path.join("templates", "btest.cfg.in"),
             os.path.join(testingFolder, "btest.cfg"))

    data = {
        "protocolName": utils.PROTOCOL_NAME,
        "protocolNameUpper": utils.PROTOCOL_NAME.upper()
    }

    copyTemplateFile(os.path.join("templates", "availability.zeek.in"),
                     data,
                     os.path.join(testsFolder, "availability.zeek"))

    copyFile(os.path.join("templates", "diff-remove-timestamps.in"),
             os.path.join(scriptsFolder, "diff-remove-timestamps"))

    copyFile(os.path.join("templates", "get-zeek-env.in"),
             os.path.join(scriptsFolder, "get-zeek-env"))

    copyFile(os.path.join("templates", "random.seed.in"),
             os.path.join(filesFolder, "random.seed"))

def writePackagingFiles(configuration, outRootFolder):
    """
    Generate and output Zeek packaging-related files for the parser. This
    creates the zkg.meta file.

    Args:
        configuration (Config): Parser configuration information.
        outRootFolder (str): Output folder path.
    """
    # Function to write out zkg.meta file
    if not utils.USES_LAYER_2:
        analyzerType = "protocol"
        if configuration.usesTCP and configuration.usesUDP:
            transportProtocolInformation = "\ntransport = IP"
        elif configuration.usesTCP:
            transportProtocolInformation = "\ntransport = TCP"
        elif configuration.usesUDP:
            transportProtocolInformation = "\ntransport = UDP"
    else:
        analyzerType = "packet"
        transportProtocolInformation = ""
    entryPointParts = configuration.entryPoint.split(".")
    if 2 != len(entryPointParts):
        entryPoint = ""
    else:
        entryPoint = entryPointParts[1]
    data = {
        "analyzerType": analyzerType,
        "transportProtocolInformation": transportProtocolInformation,
        "protocolName": utils.PROTOCOL_NAME,
        "protocolSummary": configuration.shortDescription.replace("\n", "\n    "),
        "protocolDescription": configuration.longDescription.replace("\n", "\n    "),
        "entryPoint": entryPoint,
        "protocolNameUpper": utils.PROTOCOL_NAME.upper()
    }
    copyTemplateFile(os.path.join("templates", "zkg.meta.in"),
                    data,
                    os.path.join(outRootFolder, "zkg.meta"))


    #data = {
    #    "protocolName": utils.PROTOCOL_NAME,
    #    "protocolNameLower": utils.PROTOCOL_NAME.lower(),
    #    "scope": utils.normalizedScope(entryPointScope, "object"),
    #    "entryPointName": entryPointName
    #}
    #
    #copyTemplateFile(os.path.join("templates", "standalone.spicy.in"),
    #                 data,
    #                 os.path.join(testsFolder, "standalone.spicy"))

    # TODO: Deal with trace tests?

def _writeCoreZeekFiles(configuration, scriptsFolder, zeekMainFileObject, allEnums):
    """
    Generate and output basic Zeek-related files for the parser. This creates
    the following folder and files:
    - __load__.zeek
    - main.zeek
    - dpd.sig (if one is part of the parser configuration)

    Args:
        configuration (Config): Parser configuration information.
        scriptsFolder (str): Output folder path.
        zeekMainFileObject (zeektypes.ZeekMain): Data and functions class
            related to generating main.zeek.
        allEnums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        list: List of Zeek script files (*.zeek) generated by this function.
    """
    coreFiles = []
    coreFiles.append("__load__.zeek")
    sigsString = ""
    typesString = ""
    processingString = ""
    enumString = ""
    if configuration.signatureFile is not None:
        sigsString = "@load-sigs ./dpd.sig\n"
    for scope in configuration.scopes:
        normalScope = utils.normalizedScope(scope, "")

        filePrefix = "@load ./" + normalScope.lower()

        typesString += filePrefix + "_types"
        processingString += filePrefix + "_processing"
        if utils.normalizedScope(scope, "enum") in allEnums:
            enumString += filePrefix + "_enum"
        if scope != configuration.scopes[-1]:
            typesString += "\n"
            processingString += "\n"

    data = {
        "sigsString": sigsString,
        "enumString": enumString,
        "typesString": typesString,
        "processingString": processingString
    }
    copyTemplateFile(os.path.join("templates", "__load__.zeek.in"), data,
                     os.path.join(scriptsFolder, "__load__.zeek"))

    coreFiles.append("main.zeek")
    data = {
        "protocolName": utils.PROTOCOL_NAME.upper(),
        "mainContents": zeekMainFileObject.generateMainFile(utils.USES_LAYER_2, configuration),
        "loggingFunctions": zeekMainFileObject.addLoggingFunction()
    }
    copyTemplateFile(os.path.join("templates", "main.zeek.in"), data,
                     os.path.join(scriptsFolder, "main.zeek"))

    if configuration.signatureFile is not None:
        writeDataToFile(configuration.signatureFile,
                        os.path.join(scriptsFolder, "dpd.sig"))
    return coreFiles

def _writeZeekTypeFiles(scriptsFolder, normalScope, zeekObjects):
    """
    Generate and output *_types.zeek files for the parser.

    Args:
        scriptsFolder (str): Output folder path.
        normalScope (str): Normalized scope of the entry point Object.
        zeekObjects (dict): Dictionary of Zeek Objects for the parser. The
            key is the logging structure that the object belongs to and the
            value is the object itself.

    Returns:
        list: List of Zeek script files (*.zeek) generated by this function.
    """
    contentString = ""
    for zeekLog in zeekObjects.values():
        # Is this creating the side effects?
        contentString += zeekLog.createRecord()
    data = {
        "scope": normalScope,
        "contents": contentString
    }
    zeekTypesFileName = normalScope.lower() + "_types.zeek"
    copyTemplateFile(os.path.join("templates", "zeek_types.zeek.in"), data,
                     os.path.join(scriptsFolder, zeekTypesFileName))
    return [zeekTypesFileName]

def _writeZeekProcessingFiles(scriptsFolder, normalScope, zeekObjects, enums, bitfields, objects, switches, configuration):
    """
    Generate and output *_processing.zeek files for the parser.

    Args:
        scriptsFolder (str): Output folder path.
        normalScope (str): Normalized version of the scope to generate files
            for.
        zeekObjects (dict): Dictionary of Zeek Objects for the parser. The
            key is the logging structure that the object belongs to and the
            value is the object itself.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        configuration (Config): Parser configuration information.

    Returns:
        list: List of Zeek script files (*.zeek) generated by this function.
    """
    eventString = ""
    functionString = ""
    for zeekLog in zeekObjects.values():
        eventString += zeekLog.addHook()
        functionString += "{0}\n".format(zeekLog.addFunctions(normalScope, enums, bitfields, objects, switches, configuration.scopes))
    data = {
        "scope": normalScope,
        "eventString": eventString,
        "functionString": functionString
    }
    zeekProcessingFileName = normalScope.lower() + "_processing.zeek"
    copyTemplateFile(os.path.join("templates", "zeek_processing.zeek.in"), data,
                     os.path.join(scriptsFolder, zeekProcessingFileName))
    return [zeekProcessingFileName]

def _writeZeekEnumFiles(scriptsFolder, scope, normalScope, enums):
    """
    Generate and output *_enum.zeek files (if needed) for the parser.

    Args:
        scriptsFolder (str): Output folder path.
        scope (str): The non-normalized version of the scope to generate files
            for.
        normalScope (str): Normalized version of the scope to generate files
            for.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        list: List of Zeek script files (*.zeek) generated by this function.
            An empty list is returned if no *_enum.zeek file is needed.
    """
    enumScope = utils.normalizedScope(scope, "enum")
    if enumScope in enums:
        contents = ""
        for currentEnumName in enums[enumScope]:
            contents += enums[enumScope][currentEnumName].createZeekEnumString(enumScope)
        data = {
            "scope": enumScope,
            "contents": contents
        }
        zeekEnumFile = normalScope.lower() + "_enum.zeek"
        copyTemplateFile(os.path.join("templates", "zeek_enum.zeek.in"),
                         data,
                         os.path.join(scriptsFolder, zeekEnumFile))
        return [zeekEnumFile]
    else:
        return []

# This is creating side effects somewhere...
def writeZeekFiles(configuration, outRootFolder, zeekTypes, zeekMainFileObject, bitfields, enums, objects, switches):
    """
    Generates and output Zeek-related files for the parser. This creates
    the following folder and files:
    - scripts/
    - scripts/__load__.zeek
    - scripts/main.zeek
    - scripts/dpd.sig (if one is part of the parser configuration)
    - scripts/*_types.zeek
    - scripts/*_processing.zeek
    - scripts/*_enum.zeek

    Args:
        configuration (Config): Parser configuration information.
        outRootFolder (str): Output folder path.
        zeekTypes (dict): Dictionary of Zeek Objects for the parser. The key
            is the scope that the Object belongs to. The value is a dictionary
            where the key is the logging structure that the object belongs to
            and the value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): Data and functions class
            related to generating main.zeek.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.

    Returns:
        list: List of Zeek script files (*.zeek) generated by this function.
    """
    # Create basic zeek files
    scriptsFolder = os.path.join(outRootFolder, "scripts")
    os.makedirs(scriptsFolder, exist_ok=True)

    scriptFiles = _writeCoreZeekFiles(configuration, scriptsFolder, zeekMainFileObject, enums)

    # Create all the other files
    for scope in configuration.scopes:
        normalScope = utils.normalizedScope(scope, "")
        zeekObjects = zeekTypes[normalScope]

        scriptFiles += _writeZeekTypeFiles(scriptsFolder, normalScope, zeekObjects)

        scriptFiles += _writeZeekProcessingFiles(scriptsFolder, normalScope, zeekObjects, enums, bitfields, objects, switches, configuration)

        scriptFiles += _writeZeekEnumFiles(scriptsFolder, scope, normalScope, enums)

    return scriptFiles

def generateBaseConversionFunctions(configuration):
    """
    Generates the contents of a conversion function file using boiler plate
    (empty) conversion function for all custom types.

    Args:
        configuration (Config): Parser configuration information.

    Returns:
        str: The contents of the conversion file.
    """
    returnString = ""
    if bool(configuration.customFieldTypes):
        for itemName in configuration.customFieldTypes:
            item = configuration.customFieldTypes[itemName]
            returnType = item.returnType
            emptyReturn = 0
            if "string" == returnType:
                returnType = "std::" + returnType
                emptyReturn = "\"\""
            elif "bytes" == returnType:
                returnType = "hilti::rt::Bytes"
                emptyReturn = "hilti::rt::Bytes()"
            returnString += "{0}{1} {2}(const hilti::rt::Bytes &data)".format(utils.SINGLE_TAB, returnType, item.interpretingFunction)
            returnString += "{0}{{\n{1}return {2};\n{0}}}\n".format(utils.SINGLE_TAB, utils.DOUBLE_TAB, emptyReturn)
    return returnString

def generateBaseSpicyConversionFunctions(configuration, scope):
    """
    Generates the Spicy code to import the conversion functions for custom
    types used by the parser.

    Args:
        configuration (Config): Parser configuration information.
        scope (str): The C++ namespace that the conversion functions belong to.

    Returns:
        str: The spicy code to import the conversion functions.
    """
    returnString = ""
    if bool(configuration.customFieldTypes):
        for itemName in configuration.customFieldTypes:
            item = configuration.customFieldTypes[itemName]
            returnString += "public function {0}(input: bytes) : {1} &cxxname=\"{2}::{0}\";\n\n".format(item.interpretingFunction, item.returnType, scope)
    return returnString

def _writeSpicyConfirmationFiles(analyzerFolder, entryPointName):
    """
    Generates and outputs the zeek_*.spicy file used for the parser. This file
    provides the configuration information for the protocol parser to Spicy.

    Args:
        analyzerFolder (str): Output folder path.
        entryPointName (str): Name of the entry point Object for the parser.

    Returns:
        list: List of Spicy script files (*.spicy) generated by this function.
    """
    zeekConfirmationFile = "zeek_{}.spicy".format(utils.PROTOCOL_NAME.lower())
    data = {
        "entryPoint": entryPointName + "s",
        "protocolName": utils.PROTOCOL_NAME,
        "scope": utils.normalizedScope(utils.DEFAULT_SCOPE, ""),
        "tab": utils.SINGLE_TAB
    }

    copyTemplateFile(os.path.join("templates", "zeekConfirmationFile.spicy.in"),
                     data,
                     os.path.join(analyzerFolder, zeekConfirmationFile))

    return [zeekConfirmationFile]

def _writeConversionFiles(analyzerFolder, configuration):
    """
    Generates and outputs the *.spicy and *.cc files used for parser custom
    type conversion. The *.cc file may be generated by data in the parser
    configuration if it exists, otherwise a boiler plate/templated *.cc file
    is generated. Note: The default generated file will do no real conversion,
    but will allow the parser to be built.

    Args:
        analyzerFolder (str): Output folder path.
        configuration (Config): Parser configuration information.

    Returns:
        list: List of Spicy script (*.spicy) and C++ (*.cc) files generated by
            this function.
    """
    normalScope = utils.normalizedScope(utils.CONVERSION_SCOPE, "")
    spicyConversionFile = normalScope.lower() + ".spicy"
    ccConversionFile = normalScope.lower() + ".cc"

    data = {
        "scope": normalScope,
        "functions": generateBaseSpicyConversionFunctions(configuration, normalScope)
    }
    copyTemplateFile(os.path.join("templates", "conversion.spicy.in"), data,
                     os.path.join(analyzerFolder, spicyConversionFile))

    if configuration.conversionFile is not None:
        writeDataToFile(configuration.conversionFile,
                        os.path.join(analyzerFolder, ccConversionFile))
    else:
        data = {
            "scope": normalScope,
            "functions": generateBaseConversionFunctions(configuration)
        }
        copyTemplateFile(os.path.join("templates", "conversion.cc.in"), data,
                         os.path.join(analyzerFolder, ccConversionFile))
    return [spicyConversionFile, ccConversionFile]

def _writeGenerateIDFiles(analyzerFolder):
    """
    Generates and outputs the *.spicy and *.cc files used for generating
    linking IDs within the parser.

    Args:
        analyzerFolder (str): Output folder path.

    Returns:
        list: List of Spicy script (*.spicy) and C++ (*.cc) files generated by
            this function.
    """
    normalScope = utils.normalizedScope(utils.ID_SCOPE, "")
    spicyFile = normalScope.lower() + ".spicy"
    ccFile = normalScope.lower() + ".cc"

    data = {
        "scope": normalScope
    }

    copyTemplateFile(os.path.join("templates", "generateid.spicy.in"), data,
                     os.path.join(analyzerFolder, spicyFile))

    copyTemplateFile(os.path.join("templates", "generateid.cc.in"), data,
                     os.path.join(analyzerFolder, ccFile))

    return [spicyFile, ccFile]

def determineTransportProtocols(configuration):
    """
    Determines the transport protocols (TCP or UDP) used by the parser based
    on the protocol parser configuration.

    Args:
        configuration (Config): Parser configuration information.

    Returns:
        list: List containing the transportation protocols from the set of
            "TCP" and "UDP" used by the parser. This list may be empty.
    """
    returnValue = []

    if configuration.usesTCP:
        returnValue.append("TCP")

    if configuration.usesUDP:
        returnValue.append("UDP")

    return returnValue

def _determineScopeImportLines(normalScope, crossScopeItems):
    """
    Generates import lines needed based on the scope being processed and
    previously determined inter-scope dependencies.

    Args:
        normalScope (str): The normalized scope name being processed.
        crossScopeItems (dict): A dictionary containing information about
            cross-scope dependencies. The key represents the scope that has
            dependencies. The value is dictionary with keys representing the
            scopes where the dependencies reside. The values are dictionaries
            where the keys are a subset of "enum", "object", "custom", and
            "id". The values of these dictionaries are sets with the actual
            dependency names.

    Returns:
        str: The import statements needed for that scope.
    """
    additionalScopes = ""
    if normalScope in crossScopeItems:
        for usedScope in crossScopeItems[normalScope]:
            if usedScope != "":
                additionalScopes += "import {0};\n".format(usedScope)
    return additionalScopes

def _writeSpicyScopeFiles(analyzerFolder, configuration, scope, normalScope, additionalScopeImports, entryPointScope, entryPointName, objects, bitfields, switches, enums):
    """
    Generates and outputs the *.spicy files for a specific scope used for the
    parser.

    Args:
        analyzerFolder (str): Output folder path.
        configuration (Config): Parser configuration information.
        scope (str): The non-normalized scope being processed.
        normalScope (str): The normalized scope being processed.
        additionalScopeImports (str): Additional import code lines to use.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        list: List of Spicy script files (*.spicy) generated by this function.
    """
    entryPointClass = ""
    if scope == entryPointScope:
        entryPointClass = "public type {0}s = unit {{\n{1} : {0}[];\n}};\n\n".format(entryPointName, utils.SINGLE_TAB)

    objectsString = ""
    if normalScope in objects:
        for currentObjectName in objects[normalScope]:
            # TODO: Other cases where things need to be public?
            shouldBePublic = currentObjectName == entryPointName
            objectsString += "{0}\n".format(objects[normalScope][currentObjectName].createSpicyString(configuration.customFieldTypes, bitfields, switches, enums, shouldBePublic))

    data = {
        "scope": normalScope,
        "additionalScopes": additionalScopeImports,
        "entryPoint": entryPointClass,
        "objectsString": objectsString
    }
    outputFileName = normalScope.lower() + ".spicy"
    copyTemplateFile(os.path.join("templates", "scope.spicy.in"),
                     data,
                     os.path.join(analyzerFolder, outputFileName))

    return [outputFileName]

def _determineProtocolEventsString(normalScope, entryPointScope, entryPointName, transportProtocols, configuration):
    """
    Determines if an events string is needed for the current scope and
    generates one if needed.

    Args:
        normalScope (str): The normalized scope being processed.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.
        transportProtocols (list): List containing the transportation
            protocols from the set of "TCP" and "UDP" used by the parser.
            This list may be empty.
        configuration (Config): Parser configuration information.

    Returns:
        str: If an events string is needed, the event string. Otherwise, an
            empty string.
    """
    if normalScope == utils.normalizedScope(utils.DEFAULT_SCOPE, ""):
        return generateProtocolEvents(normalScope, entryPointScope, entryPointName, transportProtocols, utils.USES_LAYER_2)
    else:
        return ""

def _determineEntryPointEventString(scope, normalScope, entryPointScope, entryPointName):
    """
    Determines if the event string for the entry point is needed for the
    current and generates one if needed.

    Args:
        scope (str): The non-normalized scope being processed.
        normalScope (str): The normalized scope being processed.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.

    Returns:
        str: If the entry point event string is needed, the event string.
            Otherwise, an empty string.
    """
    if scope == entryPointScope:
        return "export {}::{}s;\n".format(normalScope, entryPointName)
    else:
        return ""

def _determineExportString(scopedObjects, normalScope):
    """
    Determines what exports are needed for the scope and returns a string of
    the necessary exports.

    Args:
        scopedObjects (dict): Dictionary of all Objects for the parser in the
            scope being processed. The key is the name of the object and the
            value is the Object itself.
        normalScope (str): The normalized scope being processed.

    Returns:
        str: The export string needed for the scope.
    """
    exportString = ""
    for object in scopedObjects:
        if not scopedObjects[object].logWithParent or scopedObjects[object].logIndependently:
            exportString += "export {}::{}".format(normalScope, object)
            if scopedObjects[object].needsSpecificExport:
                exportString += " "
                if len(scopedObjects[object].excludedFields) < len(scopedObjects[object].includedFields):
                    exportString += "without { "
                    for field in scopedObjects[object].excludedFields:
                        exportString += field
                        if field != scopedObjects[object].excludedFields[-1]:
                            exportString += ", "
                else:
                    exportString += "with { "
                    for field in scopedObjects[object].includedFields:
                        exportString += field.name
                        if field != scopedObjects[object].includedFields[-1]:
                            exportString += ", "
                exportString += " }"
            exportString += ";\n"
    exportString += "\n"

    return exportString

def _determineObjectEventsString(scopedObjects, normalScope, bitfields):
    """
    Determine the events string for objects in a particular scope.

    Args:
        scopedObjects (dict): Dictionary of all Objects for the parser in the
            scope being processed. The key is the name of the object and the
            value is the Object itself.
        normalScope (str): The normalized scope being processed.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.

    Returns:
        str: The events string needed for the objects.
    """
    objectEvents = ""
    for object in scopedObjects.values():
        event = object.getEvent(normalScope)
        if event != []:
            objectEvents += event.generateEvent(bitfields)
    return objectEvents

def _writeSpicyEventFiles(analyzerFolder, configuration, scope, normalScope, entryPointScope, entryPointName, additionalScopeImports, transportProtocols, objects, bitfields):
    """
    Generates and outputs the *.evt files used for the parser. These files
    provides the events for the protocol parser to integrate Spicy with Zeek.

    Args:
        analyzerFolder (str): Output folder path.
        configuration (Config): Parser configuration information.
        scope (str): The non-normalized scope being processed.
        normalScope (str): The normalized scope being processed.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.
        additionalScopeImports (str): Additional import statements needed for
            the scope being processed.
        transportProtocols (list): List containing the transportation
            protocols from the set of "TCP" and "UDP" used by the parser.
            This list may be empty.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.

    Returns:
        list: List of Spicy event files (*.evt) generated by this function.
    """
    protocolEvents = _determineProtocolEventsString(normalScope, entryPointScope, entryPointName, transportProtocols, configuration)

    entryPointEvent = _determineEntryPointEventString(scope, normalScope, entryPointScope, entryPointName)

    scopedObjects = objects[normalScope]

    exportString = _determineExportString(scopedObjects, normalScope)

    objectEvents = _determineObjectEventsString(scopedObjects, normalScope, bitfields)

    data = {
        "scope": normalScope,
        "additionalScopes": additionalScopeImports,
        "protocolName": utils.PROTOCOL_NAME,
        "protocolEvents": protocolEvents,
        "entryPointEvent": entryPointEvent,
        "exportString": exportString,
        "objectEvents": objectEvents
    }
    evtFileName = normalScope.lower() + ".evt"
    copyTemplateFile(os.path.join("templates", "events.evt.in"), data,
                     os.path.join(analyzerFolder, evtFileName))
    return [evtFileName]

def _writeSpicyEnumFiles(analyzerFolder, scope, enums):
    """
    Generates and outputs the *.spicy files for enums in a specific scope used
    for the parser.

    Args:
        analyzerFolder (str): Output folder path.
        scope (str): The non-normalized scope being processed.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        list: List of Spicy script files (*.spicy) generated by this function.
    """
    enumScope = utils.normalizedScope(scope, "enum")
    if enumScope in enums:
        enumOutputFileName = enumScope.lower() + ".spicy"
        contentString = ""
        for currentEnumName in enums[enumScope]:
            contentString += "{0}\n".format(enums[enumScope][currentEnumName].createSpicyEnumString())
        data = {
            "scope": enumScope,
            "contents": contentString
        }
        copyTemplateFile(os.path.join("templates", "enum.spicy.in"), data,
                         os.path.join(analyzerFolder, enumOutputFileName))
        return [enumOutputFileName]
    else:
        return []

def writeSpicyFiles(configuration, outRootFolder, crossScopeItems, bitfields, enums, objects, switches, entryPointScope, entryPointName):
    """
    Generates and outputs the Spicy files for the parser. Specific files are
    generated by calling other functions. This creates the following folder
    and files:
    - analyzer/
    - analyzer/zeek_*.spicy
    - analyzer/*.spicy
    - analyzer/*.cc
    - analyzer/*.evt

    Args:
        configuration (Config): Parser configuration information.
        outRootFolder (str): Output folder path.
        crossScopeItems (dict): A dictionary containing information about
            cross-scope dependencies. The key represents the scope that has
            dependencies. The value is dictionary with keys representing the
            scopes where the dependencies reside. The values are dictionaries
            where the keys are a subset of "enum", "object", "custom", and
            "id". The values of these dictionaries are sets with the actual
            dependency names.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.

    Returns:
        (str, list): A tuple with the following values:
            1. The path to the analyzer folder.
            2. The list of *.spicy, *.cc, and *.evt files generated by this
                function.
    """
    # Create basic spicy files
    analyzerFolder = os.path.join(outRootFolder, "analyzer")
    os.makedirs(analyzerFolder, exist_ok=True)

    sourceFiles = _writeSpicyConfirmationFiles(analyzerFolder, entryPointName)

    sourceFiles += _writeConversionFiles(analyzerFolder, configuration)

    sourceFiles += _writeGenerateIDFiles(analyzerFolder)

    transportProtocols = determineTransportProtocols(configuration)

    # Create all the other files
    for scope in configuration.scopes:
        normalScope = utils.normalizedScope(scope, "")
        additionalScopeImports = _determineScopeImportLines(normalScope, crossScopeItems)

        # Figure out the scope file
        sourceFiles += _writeSpicyScopeFiles(analyzerFolder, configuration, scope, normalScope, additionalScopeImports, entryPointScope, entryPointName, objects, bitfields, switches, enums)

        # Figure out the event file
        sourceFiles += _writeSpicyEventFiles(analyzerFolder, configuration, scope, normalScope, entryPointScope, entryPointName, additionalScopeImports, transportProtocols, objects, bitfields)

        sourceFiles += _writeSpicyEnumFiles(analyzerFolder, scope, enums)

    return (analyzerFolder, sourceFiles)

def writeLastCMakeFile(analyzerFolder, scriptFiles, sourceFiles):
    """
    Generates and outputs the CMakeLists.txt file used to compile the parser.

    Args:
        analyzerFolder (str): Output folder path.
        scriptFiles (list): List of Zeek-related script files.
        sourceFiles (list): List of Spicy-related source files.
    """
    # Create CMakeLists.txt file with all the sources and scripts

    data = {
        "protocolName": utils.PROTOCOL_NAME,
        "sources": " ".join(sourceFiles),
        "scripts": " ".join(scriptFiles)
    }

    copyTemplateFile(os.path.join("templates", "analyzer_CMakeLists.txt.in"),
                     data,
                     os.path.join(analyzerFolder, "CMakeLists.txt"))

def writeParserFiles(configuration, outRootFolder, zeekTypes, zeekMainFileObject, crossScopeItems, bitfields, enums, objects, switches, entryPointScope, entryPointName):
    """
    Generates and outputs all parser files via calls to subfunctions.

    Args:
        configuration (Config): Parser configuration information.
        outRootFolder (str): Output folder path.
        zeekTypes (dict): Dictionary of Zeek Objects for the parser. The key
            is the scope that the Object belongs to. The value is a dictionary
            where the key is the logging structure that the object belongs to
            and the value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): Data and functions class
            related to generating main.zeek.
        crossScopeItems (dict): A dictionary containing information about
            cross-scope dependencies. The key represents the scope that has
            dependencies. The value is dictionary with keys representing the
            scopes where the dependencies reside. The values are dictionaries
            where the keys are a subset of "enum", "object", "custom", and
            "id". The values of these dictionaries are sets with the actual
            dependency names.
        bitfields (dict): Dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        enums (dict): Dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        objects (dict): Dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        switches (dict): Dictionary of all Switches for the parser broken down
            by scope, followed by the name of the Switch.
        entryPointScope (str): Scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): Name of the entry point Object for the parser.
    """
    # Create base folder
    os.makedirs(outRootFolder, exist_ok=True)
    # Basic files such as .gitignore and README
    writeBasicFiles(configuration, outRootFolder)
    # Fill in the rest of the structure
    writeCMakeFiles(outRootFolder)
    writePackagingFiles(configuration, outRootFolder)
    writeTestFiles(outRootFolder)
    # Must be called in this order...there are side effects of calling this one
    # that are required for the other one to work correctly
    folder, sourceFiles = writeSpicyFiles(configuration, outRootFolder, crossScopeItems, bitfields, enums, objects, switches, entryPointScope, entryPointName)
    # TODO: Figure out what is creating the side effects in the previous call
    scriptFiles = writeZeekFiles(configuration, outRootFolder, zeekTypes, zeekMainFileObject, bitfields, enums, objects, switches)
    writeLastCMakeFile(folder, scriptFiles, sourceFiles)
