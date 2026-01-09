#!/usr/bin/env python3
"""
IDA Domain API Reference Generator

This script generates API_REFERENCE.md from the ida-domain source code.
It parses Python source files and extracts classes, methods, enums, and
dataclasses with their docstrings to create comprehensive API documentation.

Usage:
    python bootstrap.py [--backup]

Options:
    --backup    Create a backup of the existing API_REFERENCE.md before regenerating
"""

import argparse
import ast
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple


# ANSI color codes for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"  {Colors.YELLOW}→{Colors.RESET} {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"  {Colors.GREEN}✓{Colors.RESET} {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"  {Colors.RED}✗{Colors.RESET} {message}")


def get_skill_dir() -> Path:
    """Get the directory containing this script."""
    return Path(__file__).parent.resolve()


@dataclass
class EnumMember:
    """Represents an enum member."""
    name: str
    value: str
    docstring: Optional[str] = None


@dataclass
class EnumInfo:
    """Represents an enum class."""
    name: str
    docstring: Optional[str]
    members: List[EnumMember]
    base_class: str
    lineno: int


@dataclass
class MethodInfo:
    """Represents a method or function."""
    name: str
    signature: str
    docstring: Optional[str]
    decorators: List[str]
    lineno: int
    is_property: bool = False


@dataclass
class ClassInfo:
    """Represents a class."""
    name: str
    docstring: Optional[str]
    bases: List[str]
    methods: List[MethodInfo]
    attributes: List[Tuple[str, str, Optional[str]]]  # (name, type, docstring)
    lineno: int


@dataclass
class DataclassInfo:
    """Represents a dataclass."""
    name: str
    docstring: Optional[str]
    fields: List[Tuple[str, str, Optional[str]]]  # (name, type, docstring)
    lineno: int


@dataclass
class ModuleInfo:
    """Represents a module."""
    name: str
    path: Path
    docstring: Optional[str]
    classes: List[ClassInfo]
    enums: List[EnumInfo]
    dataclasses: List[DataclassInfo]
    functions: List[MethodInfo]


class SourceParser:
    """Parses Python source files to extract API information."""

    def __init__(self, source_dir: Path):
        self.source_dir = source_dir

    def parse_module(self, module_path: Path) -> ModuleInfo:
        """Parse a single Python module."""
        with open(module_path, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)
        module_name = module_path.stem

        classes = []
        enums = []
        dataclasses_list = []
        functions = []

        module_docstring = ast.get_docstring(tree)

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                # Check if it's an enum
                if self._is_enum(node):
                    enums.append(self._parse_enum(node, source))
                # Check if it's a dataclass
                elif self._is_dataclass(node):
                    dataclasses_list.append(self._parse_dataclass(node, source))
                else:
                    classes.append(self._parse_class(node, source))
            elif isinstance(node, ast.FunctionDef):
                functions.append(self._parse_function(node))

        return ModuleInfo(
            name=module_name,
            path=module_path,
            docstring=module_docstring,
            classes=classes,
            enums=enums,
            dataclasses=dataclasses_list,
            functions=functions,
        )

    def _is_enum(self, node: ast.ClassDef) -> bool:
        """Check if a class is an enum."""
        for base in node.bases:
            base_name = self._get_name(base)
            if base_name in ("Enum", "IntEnum", "Flag", "IntFlag"):
                return True
        return False

    def _is_dataclass(self, node: ast.ClassDef) -> bool:
        """Check if a class is a dataclass."""
        for decorator in node.decorator_list:
            dec_name = self._get_name(decorator)
            if dec_name == "dataclass":
                return True
        return False

    def _get_name(self, node: ast.expr) -> str:
        """Get the name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        return ""

    def _parse_enum(self, node: ast.ClassDef, source: str) -> EnumInfo:
        """Parse an enum class."""
        members = []
        base_class = "Enum"

        for base in node.bases:
            base_name = self._get_name(base)
            if base_name in ("Enum", "IntEnum", "Flag", "IntFlag"):
                base_class = base_name

        # Get source lines for extracting inline comments
        source_lines = source.split("\n")

        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        value = self._get_value_repr(item.value)
                        # Try to get inline docstring from next statement
                        docstring = None
                        idx = node.body.index(item)
                        if idx + 1 < len(node.body):
                            next_item = node.body[idx + 1]
                            if isinstance(next_item, ast.Expr) and isinstance(
                                next_item.value, ast.Constant
                            ):
                                if isinstance(next_item.value.value, str):
                                    docstring = next_item.value.value

                        # Also check for inline comment
                        if docstring is None and hasattr(item, "lineno"):
                            line = source_lines[item.lineno - 1]
                            if "#" in line:
                                docstring = line.split("#", 1)[1].strip()

                        members.append(EnumMember(target.id, value, docstring))

        return EnumInfo(
            name=node.name,
            docstring=ast.get_docstring(node),
            members=members,
            base_class=base_class,
            lineno=node.lineno,
        )

    def _parse_dataclass(self, node: ast.ClassDef, source: str) -> DataclassInfo:
        """Parse a dataclass."""
        fields = []
        source_lines = source.split("\n")

        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                field_name = item.target.id
                field_type = self._get_annotation_str(item.annotation)

                # Try to get docstring from next statement
                docstring = None
                idx = node.body.index(item)
                if idx + 1 < len(node.body):
                    next_item = node.body[idx + 1]
                    if isinstance(next_item, ast.Expr) and isinstance(
                        next_item.value, ast.Constant
                    ):
                        if isinstance(next_item.value.value, str):
                            docstring = next_item.value.value

                # Also check for inline comment
                if docstring is None and hasattr(item, "lineno"):
                    line = source_lines[item.lineno - 1]
                    if "#" in line:
                        docstring = line.split("#", 1)[1].strip()

                fields.append((field_name, field_type, docstring))

        return DataclassInfo(
            name=node.name,
            docstring=ast.get_docstring(node),
            fields=fields,
            lineno=node.lineno,
        )

    def _parse_class(self, node: ast.ClassDef, _source: str) -> ClassInfo:
        """Parse a regular class."""
        methods = []
        attributes = []

        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(self._parse_function(item))
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                attr_name = item.target.id
                attr_type = self._get_annotation_str(item.annotation)
                attributes.append((attr_name, attr_type, None))

        bases = [self._get_base_str(base) for base in node.bases]

        return ClassInfo(
            name=node.name,
            docstring=ast.get_docstring(node),
            bases=bases,
            methods=methods,
            attributes=attributes,
            lineno=node.lineno,
        )

    def _parse_function(self, node: ast.FunctionDef) -> MethodInfo:
        """Parse a function or method."""
        decorators = []
        is_property = False

        for dec in node.decorator_list:
            dec_name = self._get_name(dec)
            decorators.append(dec_name)
            if dec_name == "property":
                is_property = True

        signature = self._get_function_signature(node)

        return MethodInfo(
            name=node.name,
            signature=signature,
            docstring=ast.get_docstring(node),
            decorators=decorators,
            lineno=node.lineno,
            is_property=is_property,
        )

    def _get_function_signature(self, node: ast.FunctionDef) -> str:
        """Get the function signature as a string."""
        args = []

        # Handle positional args
        defaults_offset = len(node.args.args) - len(node.args.defaults)

        for i, arg in enumerate(node.args.args):
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {self._get_annotation_str(arg.annotation)}"

            # Check for default value
            default_idx = i - defaults_offset
            if default_idx >= 0:
                default = node.args.defaults[default_idx]
                arg_str += f" = {self._get_value_repr(default)}"

            args.append(arg_str)

        # Handle *args
        if node.args.vararg:
            arg_str = f"*{node.args.vararg.arg}"
            if node.args.vararg.annotation:
                arg_str += f": {self._get_annotation_str(node.args.vararg.annotation)}"
            args.append(arg_str)

        # Handle keyword-only args
        kw_defaults_map = {
            i: d
            for i, d in enumerate(node.args.kw_defaults)
            if d is not None
        }
        for i, arg in enumerate(node.args.kwonlyargs):
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {self._get_annotation_str(arg.annotation)}"
            if i in kw_defaults_map:
                arg_str += f" = {self._get_value_repr(kw_defaults_map[i])}"
            args.append(arg_str)

        # Handle **kwargs
        if node.args.kwarg:
            arg_str = f"**{node.args.kwarg.arg}"
            if node.args.kwarg.annotation:
                arg_str += f": {self._get_annotation_str(node.args.kwarg.annotation)}"
            args.append(arg_str)

        # Return type
        ret_type = ""
        if node.returns:
            ret_type = f" -> {self._get_annotation_str(node.returns)}"

        return f"{node.name}({', '.join(args)}){ret_type}"

    def _get_annotation_str(self, node: ast.expr) -> str:
        """Convert an annotation AST node to a string."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Attribute):
            value = self._get_annotation_str(node.value)
            return f"{value}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            value = self._get_annotation_str(node.value)
            slice_str = self._get_annotation_str(node.slice)
            return f"{value}[{slice_str}]"
        elif isinstance(node, ast.Tuple):
            elts = ", ".join(self._get_annotation_str(e) for e in node.elts)
            return elts
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._get_annotation_str(node.left)
            right = self._get_annotation_str(node.right)
            return f"{left} | {right}"
        return "..."

    def _get_value_repr(self, node: ast.expr) -> str:
        """Get a string representation of a value node."""
        if isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_value_repr(node.value)
            return f"{value}.{node.attr}"
        elif isinstance(node, ast.Call):
            func = self._get_value_repr(node.func)
            return f"{func}(...)"
        elif isinstance(node, ast.List):
            return "[...]"
        elif isinstance(node, ast.Dict):
            return "{...}"
        elif isinstance(node, ast.Tuple):
            return "(...)"
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.USub):
                return f"-{self._get_value_repr(node.operand)}"
            elif isinstance(node.op, ast.Invert):
                return f"~{self._get_value_repr(node.operand)}"
        elif isinstance(node, ast.BinOp):
            left = self._get_value_repr(node.left)
            right = self._get_value_repr(node.right)
            if isinstance(node.op, ast.BitOr):
                return f"{left} | {right}"
            elif isinstance(node.op, ast.Add):
                return f"{left} + {right}"
        return "..."

    def _get_base_str(self, node: ast.expr) -> str:
        """Get a string representation of a base class."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_base_str(node.value)
            return f"{value}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            value = self._get_base_str(node.value)
            return f"{value}[...]"
        return "..."


class APIReferenceGenerator:
    """Generates API_REFERENCE.md from parsed module information."""

    def __init__(self, skill_dir: Path, ida_domain_dir: Path):
        self.skill_dir = skill_dir
        self.ida_domain_dir = ida_domain_dir
        self.source_dir = ida_domain_dir / "ida_domain"
        self.examples_dir = ida_domain_dir / "examples"

    def generate(self) -> str:
        """Generate the complete API reference markdown."""
        parser = SourceParser(self.source_dir)

        # Parse all modules
        modules = []
        module_order = [
            "database",
            "functions",
            "flowchart",
            "instructions",
            "operands",
            "bytes",
            "strings",
            "segments",
            "entries",
            "heads",
            "types",
            "names",
            "comments",
            "xrefs",
            "hooks",
            "signature_files",
        ]

        for module_name in module_order:
            module_path = self.source_dir / f"{module_name}.py"
            if module_path.exists():
                modules.append(parser.parse_module(module_path))

        # Also parse base.py for common utilities
        base_path = self.source_dir / "base.py"
        if base_path.exists():
            modules.append(parser.parse_module(base_path))

        # Generate markdown
        lines = []
        lines.extend(self._generate_header())
        lines.extend(self._generate_quick_start())
        lines.extend(self._generate_examples_section())
        lines.extend(self._generate_module_overview(modules))

        for module in modules:
            lines.extend(self._generate_module_section(module))

        return "\n".join(lines)

    def _generate_header(self) -> List[str]:
        """Generate the header section."""
        version = self._get_ida_domain_version()
        return [
            "# IDA Domain API Reference",
            "",
            f"> Generated from local source code: `$SKILL_DIR/ida-domain/ida_domain/`",
            f"> Version: {version}",
            f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "This reference is auto-generated from the ida-domain source code.",
            "All source files are available locally in the `$SKILL_DIR/ida-domain/` directory.",
            "",
            "## Source Code Location",
            "",
            "```",
            f"Source code:    $SKILL_DIR/ida-domain/ida_domain/",
            f"Examples:       $SKILL_DIR/ida-domain/examples/",
            f"Documentation:  $SKILL_DIR/ida-domain/docs/",
            "```",
            "",
        ]

    def _get_ida_domain_version(self) -> str:
        """Get the ida-domain version from __init__.py."""
        init_path = self.source_dir / "__init__.py"
        if init_path.exists():
            with open(init_path, "r") as f:
                content = f.read()
                match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    return match.group(1)
        return "unknown"

    def _generate_quick_start(self) -> List[str]:
        """Generate the quick start section."""
        return [
            "## Quick Start",
            "",
            "### Basic Usage",
            "",
            "```python",
            "from ida_domain import Database",
            "",
            "# Open a database",
            'with Database.open("/path/to/binary.i64") as db:',
            "    # Iterate over functions",
            "    for func in db.functions:",
            "        print(f'{func.name}: {hex(func.start_ea)}')",
            "",
            "    # Access other entities",
            "    for s in db.strings:",
            "        print(f'{hex(s.address)}: {s}')",
            "```",
            "",
            "### Database Entities",
            "",
            "All entities are accessible through the `db` handle:",
            "",
            "| Entity | Description |",
            "|--------|-------------|",
            "| `db.functions` | Function analysis and iteration |",
            "| `db.strings` | String detection and enumeration |",
            "| `db.xrefs` | Cross-reference queries |",
            "| `db.bytes` | Raw byte access and binary search |",
            "| `db.segments` | Memory segment information |",
            "| `db.types` | Type library access |",
            "| `db.names` | Symbol name management |",
            "| `db.comments` | Comment access and modification |",
            "| `db.instructions` | Instruction decoding |",
            "| `db.heads` | Instruction/data heads |",
            "| `db.entries` | Entry points |",
            "",
        ]

    def _generate_examples_section(self) -> List[str]:
        """Generate the examples section from ida-domain/examples/."""
        lines = [
            "## Code Examples",
            "",
            "Examples are available in `$SKILL_DIR/ida-domain/examples/`. Key examples:",
            "",
        ]

        example_files = [
            ("explore_database.py", "Basic database exploration"),
            ("analyze_functions.py", "Function analysis"),
            ("analyze_strings.py", "String analysis"),
            ("analyze_xrefs.py", "Cross-reference analysis"),
            ("analyze_bytes.py", "Byte-level operations"),
            ("manage_types.py", "Type management"),
            ("hooks_example.py", "Event hooks"),
            ("explore_flirt.py", "FLIRT signature exploration"),
        ]

        for filename, description in example_files:
            filepath = self.examples_dir / filename
            if filepath.exists():
                lines.append(f"### {description}")
                lines.append("")
                lines.append(f"Source: `$SKILL_DIR/ida-domain/examples/{filename}`")
                lines.append("")

                # Read and include first part of the example
                with open(filepath, "r") as f:
                    content = f.read()

                # Get a reasonable snippet (first 60 lines)
                example_lines = content.split("\n")
                snippet = "\n".join(example_lines[:min(60, len(example_lines))])
                lines.append("```python")
                lines.append(snippet)
                lines.append("```")
                lines.append("")

        return lines

    def _generate_module_overview(self, modules: List[ModuleInfo]) -> List[str]:
        """Generate the module overview section."""
        lines = [
            "## Module Overview",
            "",
            "| Module | Source File | Description |",
            "|--------|-------------|-------------|",
        ]

        for module in modules:
            rel_path = f"$SKILL_DIR/ida-domain/ida_domain/{module.name}.py"
            desc = (module.docstring or "").split("\n")[0][:60] if module.docstring else ""
            lines.append(f"| `{module.name}` | `{rel_path}` | {desc} |")

        lines.append("")
        return lines

    def _generate_module_section(self, module: ModuleInfo) -> List[str]:
        """Generate a section for a single module."""
        lines = [
            f"---",
            "",
            f"## Module: `{module.name}`",
            "",
            f"**Source:** `$SKILL_DIR/ida-domain/ida_domain/{module.name}.py`",
            "",
        ]

        if module.docstring:
            lines.append(module.docstring)
            lines.append("")

        # Enums
        if module.enums:
            lines.append("### Enums")
            lines.append("")
            for enum in module.enums:
                lines.extend(self._generate_enum_section(enum, module.name))

        # Dataclasses
        if module.dataclasses:
            lines.append("### Data Classes")
            lines.append("")
            for dc in module.dataclasses:
                lines.extend(self._generate_dataclass_section(dc, module.name))

        # Classes
        if module.classes:
            lines.append("### Classes")
            lines.append("")
            for cls in module.classes:
                lines.extend(self._generate_class_section(cls, module.name))

        # Module-level functions
        if module.functions:
            lines.append("### Functions")
            lines.append("")
            for func in module.functions:
                if not func.name.startswith("_"):
                    lines.extend(self._generate_method_section(func, module.name))

        return lines

    def _generate_enum_section(self, enum: EnumInfo, module_name: str) -> List[str]:
        """Generate documentation for an enum."""
        lines = [
            f"#### `{enum.name}` ({enum.base_class})",
            "",
            f"*Defined at line {enum.lineno} in `$SKILL_DIR/ida-domain/ida_domain/{module_name}.py`*",
            "",
        ]

        if enum.docstring:
            lines.append(enum.docstring)
            lines.append("")

        if enum.members:
            lines.append("| Member | Value | Description |")
            lines.append("|--------|-------|-------------|")
            for member in enum.members:
                doc = member.docstring or ""
                lines.append(f"| `{member.name}` | `{member.value}` | {doc} |")
            lines.append("")

        return lines

    def _generate_dataclass_section(self, dc: DataclassInfo, module_name: str) -> List[str]:
        """Generate documentation for a dataclass."""
        lines = [
            f"#### `{dc.name}`",
            "",
            f"*Defined at line {dc.lineno} in `$SKILL_DIR/ida-domain/ida_domain/{module_name}.py`*",
            "",
        ]

        if dc.docstring:
            lines.append(dc.docstring)
            lines.append("")

        if dc.fields:
            lines.append("**Fields:**")
            lines.append("")
            lines.append("| Field | Type | Description |")
            lines.append("|-------|------|-------------|")
            for name, type_str, doc in dc.fields:
                doc = doc or ""
                lines.append(f"| `{name}` | `{type_str}` | {doc} |")
            lines.append("")

        return lines

    def _generate_class_section(self, cls: ClassInfo, module_name: str) -> List[str]:
        """Generate documentation for a class."""
        bases_str = ", ".join(cls.bases) if cls.bases else ""
        lines = [
            f"#### `{cls.name}`" + (f" (extends {bases_str})" if bases_str else ""),
            "",
            f"*Defined at line {cls.lineno} in `$SKILL_DIR/ida-domain/ida_domain/{module_name}.py`*",
            "",
        ]

        if cls.docstring:
            lines.append(cls.docstring)
            lines.append("")

        # Properties
        properties = [m for m in cls.methods if m.is_property and not m.name.startswith("_")]
        if properties:
            lines.append("**Properties:**")
            lines.append("")
            for prop in properties:
                doc = (prop.docstring or "").split("\n")[0]
                lines.append(f"- `{prop.name}` - {doc}")
            lines.append("")

        # Methods
        methods = [m for m in cls.methods if not m.is_property and not m.name.startswith("_")]
        if methods:
            lines.append("**Methods:**")
            lines.append("")
            for method in methods:
                lines.extend(self._generate_method_section(method, module_name, is_method=True))

        return lines

    def _generate_method_section(
        self, method: MethodInfo, _module_name: str, is_method: bool = False
    ) -> List[str]:
        """Generate documentation for a method or function."""
        lines = []

        prefix = "- " if is_method else "##### "
        sig = method.signature

        # For methods, simplify the signature display
        if is_method:
            # Remove 'self' from display
            sig = re.sub(r"\bself,?\s*", "", sig)
            doc_first_line = (method.docstring or "").split("\n")[0]
            lines.append(f"{prefix}`{sig}` - {doc_first_line}")
        else:
            lines.append(f"{prefix}`{sig}`")
            lines.append("")
            if method.docstring:
                lines.append(method.docstring)
                lines.append("")

        return lines


def backup_api_reference(skill_dir: Path) -> Optional[Path]:
    """Create a backup of the existing API_REFERENCE.md."""
    api_ref_path = skill_dir / "API_REFERENCE.md"
    if not api_ref_path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = skill_dir / f"API_REFERENCE.md.backup.{timestamp}"
    shutil.copy2(api_ref_path, backup_path)
    return backup_path


def generate_api_reference(skill_dir: Path, create_backup: bool = True) -> bool:
    """
    Generate API_REFERENCE.md from ida-domain source code.

    Args:
        skill_dir: Path to the skill directory
        create_backup: Whether to backup existing API_REFERENCE.md

    Returns:
        True if successful, False otherwise
    """
    ida_domain_dir = skill_dir / "ida-domain"

    if not ida_domain_dir.exists():
        print_error("ida-domain directory not found. Run setup.py first.")
        return False

    source_dir = ida_domain_dir / "ida_domain"
    if not source_dir.exists():
        print_error("ida-domain/ida_domain source directory not found.")
        return False

    # Create backup if requested
    if create_backup:
        backup_path = backup_api_reference(skill_dir)
        if backup_path:
            print_info(f"Backed up existing API_REFERENCE.md to {backup_path.name}")

    # Generate the reference
    print_info("Parsing ida-domain source code...")
    generator = APIReferenceGenerator(skill_dir, ida_domain_dir)

    try:
        content = generator.generate()
    except Exception as e:
        print_error(f"Failed to generate API reference: {e}")
        return False

    # Write the new API_REFERENCE.md
    api_ref_path = skill_dir / "API_REFERENCE.md"
    try:
        with open(api_ref_path, "w", encoding="utf-8") as f:
            f.write(content)
        print_success(f"Generated API_REFERENCE.md ({len(content)} bytes)")
        return True
    except Exception as e:
        print_error(f"Failed to write API_REFERENCE.md: {e}")
        return False


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate API_REFERENCE.md from ida-domain source code"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create a backup of existing API_REFERENCE.md",
    )
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}IDA Domain API Reference Generator{Colors.RESET}")
    print("=" * 50)

    skill_dir = get_skill_dir()

    if generate_api_reference(skill_dir, create_backup=not args.no_backup):
        print()
        print(f"{Colors.GREEN}✓{Colors.RESET} API reference generated successfully")
        return 0
    else:
        print()
        print(f"{Colors.RED}✗{Colors.RESET} Failed to generate API reference")
        return 1


if __name__ == "__main__":
    sys.exit(main())
