#!/usr/bin/env python3
"""
Ansible Playbook Variables Extractor

This script traverses an Ansible playbook directory structure and extracts all variables
that the playbook expects, including those in roles, templates, and defaults.
"""

import os
import sys
import re
import yaml
import argparse
from collections import defaultdict
import json


class AnsibleVariablesExtractor:
    def __init__(self, playbook_dir):
        self.playbook_dir = os.path.abspath(playbook_dir)
        self.variables = defaultdict(set)
        self.variable_sources = defaultdict(list)
        self.jinja2_pattern = re.compile(r"{{[\s]*([a-zA-Z0-9_\.\[\]\"\']+(?:\s*\|\s*[a-zA-Z0-9_]+)*)[\s]*}}")
        self.jinja2_if_pattern = re.compile(r"{%[\s]*if[\s]+(.*?)[\s]*%}")
        self.yaml_var_pattern = re.compile(r"{{\s*([a-zA-Z0-9_\.]+)\s*}}")
        self.when_condition_pattern = re.compile(r"when:[\s]*(.*)")

    def extract_variables(self):
        """
        Main method to extract variables from the playbook structure
        """
        print(f"Analyzing Ansible playbook in: {self.playbook_dir}")
        
        # Find and process main playbook files
        for root, _, files in os.walk(self.playbook_dir):
            # Skip .git and other hidden directories
            if any(part.startswith('.') for part in root.split(os.sep)):
                continue

            for file in files:
                if self._is_ansible_file(file):
                    file_path = os.path.join(root, file)
                    self._process_file(file_path)
                    print(f"Processed: {os.path.relpath(file_path, self.playbook_dir)}")
        
        return dict(self.variables), dict(self.variable_sources)

    def _is_ansible_file(self, filename):
        """Check if a file is an Ansible file that might contain variables"""
        ansible_extensions = ['.yml', '.yaml', '.j2']
        return (any(filename.endswith(ext) for ext in ansible_extensions) and 
                not filename.startswith('.'))

    def _process_file(self, file_path):
        """Process a single file to extract variables"""
        rel_path = os.path.relpath(file_path, self.playbook_dir)
        file_type = self._get_file_type(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if file_path.endswith('.j2'):
                # Handle Jinja2 templates
                self._extract_from_jinja2(content, rel_path)
            elif file_path.endswith(('.yml', '.yaml')):
                # Handle YAML files
                self._extract_from_yaml(content, rel_path)
        except Exception as e:
            print(f"Error processing {rel_path}: {str(e)}", file=sys.stderr)

    def _get_file_type(self, file_path):
        """Determine the type of Ansible file"""
        rel_path = os.path.relpath(file_path, self.playbook_dir)
        
        if 'roles/' in rel_path:
            if '/defaults/' in rel_path:
                return 'role_defaults'
            elif '/vars/' in rel_path:
                return 'role_vars'
            elif '/tasks/' in rel_path:
                return 'role_tasks'
            elif '/templates/' in rel_path:
                return 'role_templates'
            return 'role_other'
        elif 'group_vars/' in rel_path:
            return 'group_vars'
        elif 'host_vars/' in rel_path:
            return 'host_vars'
        elif file_path.endswith('.j2'):
            return 'template'
        else:
            return 'playbook'

    def _extract_from_jinja2(self, content, source):
        """Extract variables from Jinja2 templates"""
        # Find standard {{ variable }} patterns
        for match in self.jinja2_pattern.finditer(content):
            var_full = match.group(1).strip()
            # Handle filter expressions like {{ var | default('value') }}
            var_name = var_full.split('|')[0].strip() if '|' in var_full else var_full
            # Remove any quotes around variable names
            var_name = var_name.strip('\'"')
            
            # Skip variables that are clearly not meant to be external inputs
            if not self._should_ignore_variable(var_name):
                self._add_variable(var_name, source, 'template')
        
        # Find variables in {% if condition %} statements
        for match in self.jinja2_if_pattern.finditer(content):
            condition = match.group(1).strip()
            # Extract variables from conditions like "foo is defined" or "bar == 'value'"
            var_matches = re.findall(r'([a-zA-Z0-9_\.]+)\s+(?:is|==|!=|>=|<=|>|<|defined)', condition)
            for var_name in var_matches:
                if not self._should_ignore_variable(var_name):
                    self._add_variable(var_name, source, 'template_condition')

    def _extract_from_yaml(self, content, source):
        """Extract variables from YAML files"""
        try:
            # Try to load as YAML
            data = yaml.safe_load(content)
            
            # Skip if not valid YAML or empty
            if not data:
                print(f"Empty or invalid YAML in {source}", file=sys.stderr)
                return
                
            # Process vars sections and defaults
            self._extract_vars_from_yaml_data(data, source)
            
            # Look for string interpolation in YAML using regex
            yaml_vars = self.yaml_var_pattern.findall(content)
            for var_name in yaml_vars:
                self._add_variable(var_name, source, 'yaml_interpolation')
                
            # Look for 'when' conditions which often contain variables
            when_conditions = self.when_condition_pattern.findall(content)
            for condition in when_conditions:
                # Extract variable names from conditions
                var_matches = re.findall(r'([a-zA-Z0-9_\.]+)\s+(?:is|==|!=|>=|<=|>|<|defined)', condition)
                for var_name in var_matches:
                    if not self._should_ignore_variable(var_name):
                        self._add_variable(var_name, source, 'when_condition')
                
        except yaml.YAMLError as e:
            print(f"YAML parsing error in {source}: {str(e)}", file=sys.stderr)

    def _extract_vars_from_yaml_data(self, data, source, prefix=''):
        """Recursively extract variables from YAML data structure"""
        if isinstance(data, dict):
            # Check for vars section
            if 'vars' in data and isinstance(data['vars'], dict):
                for var_name, value in data['vars'].items():
                    full_name = f"{prefix}{var_name}" if prefix else var_name
                    self._add_variable(full_name, source, 'vars_section', is_defined=True)
                    
            # Check for vars_files section
            if 'vars_files' in data and isinstance(data['vars_files'], list):
                for file_entry in data['vars_files']:
                    if isinstance(file_entry, str):
                        self._add_variable(file_entry, source, 'vars_files', is_defined=False)
            
            # Check for default values in role defaults
            if 'defaults' in source or 'defaults.yml' in source:
                for var_name, value in data.items():
                    self._add_variable(var_name, source, 'role_defaults', is_defined=True)
            
            # Process tasks with variables
            if 'tasks' in data and isinstance(data['tasks'], list):
                for task in data['tasks']:
                    if isinstance(task, dict):
                        # Look for 'vars' in tasks
                        if 'vars' in task and isinstance(task['vars'], dict):
                            for var_name, value in task['vars'].items():
                                self._add_variable(var_name, source, 'task_vars', is_defined=True)
                        
                        # Look for variables in task parameters
                        for key, value in task.items():
                            if key not in ['name', 'tags', 'become', 'become_user']:
                                if isinstance(value, str) and '{{' in value:
                                    vars_in_value = self.jinja2_pattern.findall(value)
                                    for var_name in vars_in_value:
                                        if not self._should_ignore_variable(var_name):
                                            self._add_variable(var_name, source, 'task_parameter')
            
            # Check for roles section
            if 'roles' in data and isinstance(data['roles'], list):
                for role in data['roles']:
                    if isinstance(role, dict) and 'role' in role:
                        role_name = role['role']
                        # Variables often passed to roles
                        if 'vars' in role and isinstance(role['vars'], dict):
                            for var_name, value in role['vars'].items():
                                self._add_variable(var_name, source, f'role_param:{role_name}', is_defined=True)
            
            # Recurse through the dictionary
            for key, value in data.items():
                new_prefix = f"{prefix}{key}." if prefix else f"{key}."
                self._extract_vars_from_yaml_data(value, source, new_prefix)
                
        elif isinstance(data, list):
            # Recurse through lists
            for item in data:
                self._extract_vars_from_yaml_data(item, source, prefix)

    def _add_variable(self, var_name, source, var_type, is_defined=False):
        """Add a variable to the collection"""
        # Clean up variable name
        var_name = var_name.strip()
        
        # Skip certain patterns
        if self._should_ignore_variable(var_name):
            return
            
        # Add to dictionary of variables
        if is_defined:
            self.variables[var_name].add('defined')
        else:
            self.variables[var_name].add('used')
            
        # Record where this variable was found
        self.variable_sources[var_name].append({
            'source': source,
            'type': var_type
        })

    def _should_ignore_variable(self, var_name):
        """Check if a variable should be ignored"""
        # Skip common Ansible built-ins and obviously non-variables
        built_ins = ['item', 'ansible_facts', 'ansible_', 'inventory_hostname', 'hostvars', 'groups', 'group_names', 'play_hosts']
        
        return (any(var_name.startswith(prefix) for prefix in built_ins) or
                var_name in ['True', 'False', 'None', 'null', 'lookup', 'range', 'dict', 'list'] or
                '|' in var_name or  # Likely a filter
                '(' in var_name or  # Likely a function call
                var_name.strip() == '')

    def generate_report(self, just_variables=False):
        """Generate a structured report of the variables"""
        required_vars = []
        optional_vars = []
        defined_vars = []
        
        for var_name, status in self.variables.items():
            if just_variables:
                var_info = {'name': var_name}
            else:
                var_info = {
                    'name': var_name,
                    'sources': self.variable_sources[var_name]
                }
            
            if 'defined' in status and 'used' in status:
                defined_vars.append(var_info)
            elif 'defined' in status:
                optional_vars.append(var_info)
            else:  # only 'used'
                required_vars.append(var_info)
        
        # Sort by variable name
        required_vars.sort(key=lambda x: x['name'])
        optional_vars.sort(key=lambda x: x['name'])
        defined_vars.sort(key=lambda x: x['name'])
        
        return {
            'required_variables': required_vars,
            'optional_variables': optional_vars,
            'defined_variables': defined_vars
        }


def main():
    parser = argparse.ArgumentParser(description='Extract variables from Ansible playbooks')
    parser.add_argument('playbook_dir', help='Path to the Ansible playbook directory')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--format', '-f', choices=['json', 'yaml', 'text'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--vars', '-v', action='store_true', help='Show just variables')
    args = parser.parse_args()
    
    extractor = AnsibleVariablesExtractor(args.playbook_dir)
    extractor.extract_variables()
    report = extractor.generate_report(args.vars)
    
    # Format output
    if args.format == 'json':
        output = json.dumps(report, indent=2)
    elif args.format == 'yaml':
        output = yaml.dump(report, default_flow_style=False)
    else:  # text
        output = format_text_report(report)
    
    # Write output
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)


def format_text_report(report):
    """Format the report as readable text"""
    lines = []
    
    lines.append("=== ANSIBLE PLAYBOOK VARIABLES REPORT ===\n")
    
    lines.append(f"Required Variables ({len(report['required_variables'])})")
    lines.append("These variables are used but not defined in the playbook:")
    lines.append("-" * 50)
    
    for var in report['required_variables']:
        lines.append(f"* {var['name']}")
        if var.get('sources'):
            for source in var['sources'][:3]:  # Limit to 3 sources to keep output manageable
                lines.append(f"  - {source['source']} ({source['type']})")
            if len(var['sources']) > 3:
                lines.append(f"  - ... and {len(var['sources']) - 3} more occurrences")
    
    if not report['required_variables']:
        lines.append("None found.")
    
    lines.append("\n")
    lines.append(f"Optional Variables ({len(report['optional_variables'])})")
    lines.append("These variables are defined but not used in the playbook:")
    lines.append("-" * 50)
    
    for var in report['optional_variables']:
        lines.append(f"* {var['name']}")
        if var.get('sources'):
            for source in var['sources'][:2]:
                lines.append(f"  - {source['source']} ({source['type']})")
            if len(var['sources']) > 2:
                lines.append(f"  - ... and {len(var['sources']) - 2} more occurrences")
    
    if not report['optional_variables']:
        lines.append("None found.")
    
    lines.append("\n")
    lines.append(f"Defined and Used Variables ({len(report['defined_variables'])})")
    lines.append("These variables are both defined and used in the playbook:")
    lines.append("-" * 50)
    
    for var in report['defined_variables']:
        lines.append(f"* {var['name']}")
        if var.get('sources'):
            for source in var['sources'][:2]:
                lines.append(f"  - {source['source']} ({source['type']})")
            if len(var['sources']) > 2:
                lines.append(f"  - ... and {len(var['sources']) - 2} more occurrences")
        
    if not report['defined_variables']:
        lines.append("None found.")
    
    return "\n".join(lines)

if __name__ == '__main__':
    main()