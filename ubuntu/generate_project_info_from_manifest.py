# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

'''
generate_project_info_from_manifest.py

This script interacts with a file data API, processes XML data, and generates project information files.
'''

from __future__ import print_function
import argparse
import collections
import os
import requests
from lxml import etree
from color_logger import logger


def parse_from_string(xml_string):
    """
    Parses an XML string into an ElementTree object.

    Args:
    -----
    - xml_string (str): The XML string to parse.

    Returns:
    --------
    - Element: The parsed XML as an ElementTree object.
    """
    from builtins import bytes
    if isinstance(xml_string, str):
        xml_string = bytes(xml_string, encoding='utf-8')
    return etree.fromstring(xml_string)


def etree_to_dict(node):
    """
    Converts an ElementTree node into a dictionary representation.

    Args:
    -----
    - node (Element): The XML node to convert.

    Returns:
    --------
    - dict: Dictionary representation of the XML node.
    """
    d = {node.tag: {} if node.attrib else None}
    children = list(node)

    if children:
        dd = collections.defaultdict(list)
        for dc in map(etree_to_dict, children):
            for key, val in list(dc.items()):
                dd[str(key)].append(val)
        d = {
            node.tag: {str(key): val[0] if len(val) == 1 else val
                       for key, val in list(dd.items())}}
    if node.attrib:
        d[node.tag].update((str(k), v) for k, v in list(node.attrib.items()))
    if node.text:
        text = node.text.strip()
        if children or node.attrib:
            d[node.tag]['#text'] = text
        else:
            d[node.tag] = text
    return d


def write_to_file(workspace, projects, out_path=None):
    """
    Writes project information to a specified file.

    Args:
    -----
    - workspace (str): The workspace directory.
    - projects (list): List of project dictionaries.
    - out_path (str): Optional path to the output file.
    """
    if not out_path:
        out_path = os.path.join(workspace,'project_info.txt')
    with open(out_path, 'w') as f:
        for project in projects:
            prj_path = project.get('path')
            prj_ship_val = project.get('x-ship')
            if prj_ship_val == 'oss':
                prj_ship_val = 'oss'
            else:
                prj_ship_val = 'prop'
            f.write("{}\t{}\n".format(prj_path, prj_ship_val))
    return


def get_elements(xml_root, element_name):
    """
    Retrieves all elements with a specified name from the XML root.

    Args:
    -----
    - xml_root (Element): The root of the XML tree.
    - element_name (str): The name of the elements to find.

    Returns:
    --------
    - list: List of found elements.
    """
    return xml_root.findall(element_name)


def create_project_info_file(workspace, project, group, out_path=None):
    """
    Creates a project information file based on the provided parameters.

    Args:
    -----
    - workspace (str): The workspace directory.
    - project (str): The name of the project.
    - group (str): Optional group name for filtering projects.
    - out_path (str): Optional path to the output file.
    """
    manifest_file  = os.path.join(workspace, '.repo/manifests/default.xml')
    if os.path.exists(manifest_file):
        xml_root = etree.parse(manifest_file)
        xml_root.findall('project')
        projects = get_elements(xml_root.getroot(), 'project')
        if group:
            logger.info(get_comp_tag_for_groups(projects, group))
        else:
            write_to_file(workspace, projects, out_path)
    else:
        logger.warning("default.xml not present in .repo/manifests/. All packages will default to 'oss' category without manifest information.")
    return


def get_comp_tag_for_groups(projects, group):
    """
    Retrieves the component tag for projects belonging to a specified group.

    Args:
    -----
    - projects (list): List of project dictionaries.
    - group (str): The group name to filter by.

    Returns:
    --------
    - str or None: Component tag string or None if not found.
    """
    for project in projects:
        if project.get('groups') == group:
            if project.get('x-component-tag'):
                return project.get('x-component-tag').replace('refs/tags/', '')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workspace_tree')
    parser.add_argument('manifest_project')
    parser.add_argument('manifest_branch')
    parser.add_argument('--au')
    parser.add_argument('--group')
    parser.add_argument('--info_out', required=False, help='Path to keep package_info.txt, default <workspace>/project_info.txt')
    args = parser.parse_args()
    create_project_info_file(args.workspace_tree,
        args.manifest_project, args.manifest_branch, args.au, args.group, args.info_out)


if __name__ == "__main__":
    main()
