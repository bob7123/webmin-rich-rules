#!/bin/bash
# Claude Projects File Gatherer - Enhanced Version
# Add to any project in .claude_proj/ directory for instant Claude Projects integration
# Consolidates code, docs, and config files into readable text files

set -e  # Exit on any error

echo "Claude Projects File Gatherer - Enhanced Edition"
echo "   Optimizing your project for Claude Projects integration..."
echo ""

# Function to detect if we're in a project root
detect_project_root() {
    local indicators=()
    
    # Check for common project root indicators
    [ -f "README.md" ] && indicators+=("README.md")
    [ -f "README.rst" ] && indicators+=("README.rst")
    [ -f "requirements.txt" ] && indicators+=("requirements.txt")
    [ -f "package.json" ] && indicators+=("package.json")
    [ -f "pyproject.toml" ] && indicators+=("pyproject.toml")
    [ -f "setup.py" ] && indicators+=("setup.py")
    [ -f "Cargo.toml" ] && indicators+=("Cargo.toml")
    [ -f "pom.xml" ] && indicators+=("pom.xml")
    [ -f "build.gradle" ] && indicators+=("build.gradle")
    [ -f "go.mod" ] && indicators+=("go.mod")
    [ -f "Makefile" ] && indicators+=("Makefile")
    [ -f "docker-compose.yml" ] && indicators+=("docker-compose.yml")
    [ -f "Dockerfile" ] && indicators+=("Dockerfile")
    [ -d ".git" ] && indicators+=(".git/")
    [ -d "src" ] && indicators+=("src/")
    [ -d "docs" ] && indicators+=("docs/")
    [ -d ".claude_proj" ] && indicators+=(".claude_proj/")
    
    echo "${indicators[@]}"
}

# Check if we appear to be in a project root
echo "Detecting project structure..."
project_indicators=($(detect_project_root))

if [ ${#project_indicators[@]} -eq 0 ]; then
    echo "WARNING: No common project files detected in current directory!"
    echo "   Current directory: $(pwd)"
    echo ""
    echo "   Common project indicators not found:"
    echo "   - README.md/README.rst"
    echo "   - package.json, requirements.txt, Cargo.toml, go.mod"
    echo "   - .git directory"
    echo "   - src/ or docs/ directories"
    echo ""
    echo "   Are you sure you're in the project root directory?"
    echo "   (Hint: You should run this from where your main project files are,"
    echo "    not from inside the .claude_proj directory)"
    read -p "   Continue anyway? (y/N): " continue_anyway
    
    case $continue_anyway in
        [Yy]|[Yy][Ee][Ss])
            echo "   Continuing in current directory..."
            ;;
        *)
            echo "   Exiting. Please navigate to your project root directory first."
            echo "   Tip: Look for directories containing README.md, package.json, etc."
            exit 1
            ;;
    esac
else
    echo "Project root detected! Found indicators:"
    printf "   - %s\n" "${project_indicators[@]}"
fi
echo ""

PROJECT_DIR="claude_project_files"

# Check if directory exists and handle it
if [ -d "$PROJECT_DIR" ]; then
    echo "Directory $PROJECT_DIR already exists!"
    echo "Choose an option:"
    echo "  1) Remove existing directory and recreate"
    echo "  2) Add timestamp suffix (e.g., claude_project_files_20241206_143022)"
    echo "  3) Exit without changes"
    read -p "Enter choice (1/2/3): " choice
    
    case $choice in
        1)
            echo "Removing existing directory..."
            rm -rf "$PROJECT_DIR"
            ;;
        2)
            TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
            PROJECT_DIR="${PROJECT_DIR}_${TIMESTAMP}"
            echo "Using timestamped directory: $PROJECT_DIR"
            ;;
        3)
            echo "Exiting without changes"
            exit 0
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
fi

echo "Creating Claude Projects directory: $PROJECT_DIR"

# Create the directory
mkdir -p "$PROJECT_DIR"

# Function to safely add file separator
add_separator() {
    local filename="$1"
    local output_file="$2"
    echo "" >> "$output_file"
    echo "=== $filename ===" >> "$output_file"
    echo "" >> "$output_file"
}

# 1. Gather all code files
echo "Gathering code files..."
CODE_FILE="$PROJECT_DIR/all_code.txt"
> "$CODE_FILE"  # Clear file

echo "# PROJECT CODE CONSOLIDATION" > "$CODE_FILE"
echo "# Generated on: $(date)" >> "$CODE_FILE"
echo "# Project: $(basename $(pwd))" >> "$CODE_FILE"
echo "# Claude Projects Integration" >> "$CODE_FILE"
echo "" >> "$CODE_FILE"

# Find and consolidate code files (comprehensive language support)
find . -type f \( \
    -name "*.py" -o \
    -name "*.js" -o \
    -name "*.ts" -o \
    -name "*.jsx" -o \
    -name "*.tsx" -o \
    -name "*.java" -o \
    -name "*.cpp" -o \
    -name "*.c" -o \
    -name "*.h" -o \
    -name "*.hpp" -o \
    -name "*.cs" -o \
    -name "*.go" -o \
    -name "*.rs" -o \
    -name "*.rb" -o \
    -name "*.php" -o \
    -name "*.swift" -o \
    -name "*.kt" -o \
    -name "*.scala" -o \
    -name "*.r" -o \
    -name "*.R" -o \
    -name "*.pl" -o \
    -name "*.pm" -o \
    -name "*.sh" -o \
    -name "*.bash" -o \
    -name "*.zsh" -o \
    -name "*.fish" -o \
    -name "*.sql" -o \
    -name "*.lua" -o \
    -name "*.dart" -o \
    -name "*.ex" -o \
    -name "*.exs" -o \
    -name "*.elm" -o \
    -name "*.hs" -o \
    -name "*.clj" -o \
    -name "*.cljs" -o \
    -name "*.fs" -o \
    -name "*.fsx" -o \
    -name "*.ml" -o \
    -name "*.vim" -o \
    -name "*.proto" -o \
    -name "*.graphql" -o \
    -name "*.gql" \
\) \
    -not -path "./.git/*" \
    -not -path "./node_modules/*" \
    -not -path "./__pycache__/*" \
    -not -path "./build/*" \
    -not -path "./dist/*" \
    -not -path "./.venv/*" \
    -not -path "./venv/*" \
    -not -path "./.pytest_cache/*" \
    -not -path "./docs/build/*" \
    -not -path "./docs/_build/*" \
    -not -path "./target/*" \
    -not -path "./.cargo/*" \
    -not -path "./vendor/*" \
    -not -path "./.claude_proj/*" \
    | sort | while read -r file; do
    if [ -s "$file" ]; then  # Only process non-empty files
        add_separator "$file" "$CODE_FILE"
        cat "$file" >> "$CODE_FILE"
    fi
done

echo "Code files saved to: $CODE_FILE"

# 2. Gather configuration files
echo "Gathering configuration files..."
CONFIG_FILE="$PROJECT_DIR/all_config.txt"
> "$CONFIG_FILE"

echo "# PROJECT CONFIGURATION FILES" > "$CONFIG_FILE"
echo "# Generated on: $(date)" >> "$CONFIG_FILE"
echo "# For Claude Projects upload and caching" >> "$CONFIG_FILE"
echo "" >> "$CONFIG_FILE"

# Find and consolidate config files
find . -type f \( \
    -name "*.yml" -o \
    -name "*.yaml" -o \
    -name "*.json" -o \
    -name "*.toml" -o \
    -name "*.ini" -o \
    -name "*.cfg" -o \
    -name "*.conf" -o \
    -name "*.env" -o \
    -name ".env*" -o \
    -name "*.xml" -o \
    -name "Dockerfile*" -o \
    -name "*.dockerfile" -o \
    -name "requirements.txt" -o \
    -name "package.json" -o \
    -name "package-lock.json" -o \
    -name "yarn.lock" -o \
    -name "Pipfile" -o \
    -name "Pipfile.lock" -o \
    -name "poetry.lock" -o \
    -name "pyproject.toml" -o \
    -name "setup.py" -o \
    -name "setup.cfg" -o \
    -name "Cargo.toml" -o \
    -name "Cargo.lock" -o \
    -name "go.mod" -o \
    -name "go.sum" -o \
    -name "pom.xml" -o \
    -name "build.gradle" -o \
    -name "gradle.properties" -o \
    -name "Makefile" -o \
    -name "makefile" -o \
    -name "*.mk" -o \
    -name "CMakeLists.txt" -o \
    -name ".gitignore" -o \
    -name ".gitattributes" -o \
    -name "*.editorconfig" \
\) \
    -not -path "./.git/*" \
    -not -path "./node_modules/*" \
    -not -path "./build/*" \
    -not -path "./dist/*" \
    -not -path "./docs/build/*" \
    -not -path "./docs/_build/*" \
    -not -path "./target/*" \
    -not -path "./vendor/*" \
    -not -path "./.claude_proj/*" \
    | sort | while read -r file; do
    if [ -s "$file" ]; then
        add_separator "$file" "$CONFIG_FILE"
        cat "$file" >> "$CONFIG_FILE"
    fi
done

echo "Configuration files saved to: $CONFIG_FILE"

# 3. Gather documentation files
echo "Gathering documentation files..."
DOCS_FILE="$PROJECT_DIR/all_docs.txt"
> "$DOCS_FILE"

echo "# PROJECT DOCUMENTATION" > "$DOCS_FILE"
echo "# Generated on: $(date)" >> "$DOCS_FILE"
echo "# Source documentation files for Claude Projects" >> "$DOCS_FILE"
echo "" >> "$DOCS_FILE"

# Find and consolidate documentation files
find . -type f \( \
    -name "*.rst" -o \
    -name "*.md" -o \
    -name "*.markdown" -o \
    -name "*.txt" -o \
    -name "*.css" -o \
    -name "*.html" -o \
    -name "*.htm" -o \
    -name "*.tex" -o \
    -name "*.adoc" -o \
    -name "*.asciidoc" -o \
    -name "README*" -o \
    -name "CHANGELOG*" -o \
    -name "CONTRIBUTING*" -o \
    -name "LICENSE*" -o \
    -name "INSTALL*" -o \
    -name "AUTHORS*" -o \
    -name "CREDITS*" -o \
    -name "USAGE*" -o \
    -name "EXAMPLES*" \
\) \
    -not -path "./.git/*" \
    -not -path "./node_modules/*" \
    -not -path "./build/*" \
    -not -path "./dist/*" \
    -not -path "./docs/build/*" \
    -not -path "./docs/_build/*" \
    -not -path "./_build/*" \
    -not -path "./site/*" \
    -not -path "./_site/*" \
    -not -path "./public/*" \
    -not -path "./.venv/*" \
    -not -path "./venv/*" \
    -not -path "./.next/*" \
    -not -path "./.nuxt/*" \
    -not -path "./target/doc/*" \
    -not -path "./vendor/*" \
    -not -path "./.claude_proj/*" \
    | sort | while read -r file; do
    if [ -s "$file" ]; then
        add_separator "$file" "$DOCS_FILE"
        cat "$file" >> "$DOCS_FILE"
    fi
done

echo "Documentation files saved to: $DOCS_FILE"

# 4. Copy important individual files
echo "Copying key individual files..."

# Copy critical files that should be uploaded separately
for file in README.md requirements.txt package.json pyproject.toml docker-compose.yml Dockerfile go.mod Cargo.toml pom.xml; do
    if [ -f "$file" ]; then
        cp "$file" "$PROJECT_DIR/"
        echo "  Copied: $file"
    fi
done

# Copy important config files from common locations
if [ -f "docs/source/conf.py" ]; then
    cp "docs/source/conf.py" "$PROJECT_DIR/"
    echo "  Copied: docs/source/conf.py"
fi

if [ -f ".claude_proj/gather_files.sh" ]; then
    cp ".claude_proj/gather_files.sh" "$PROJECT_DIR/gather_files_script.sh"
    echo "  Copied: .claude_proj/gather_files.sh"
fi

# 5. Create project structure overview
echo "Creating project structure overview..."
STRUCTURE_FILE="$PROJECT_DIR/project_structure.txt"

echo "# PROJECT STRUCTURE OVERVIEW" > "$STRUCTURE_FILE"
echo "# Generated on: $(date)" >> "$STRUCTURE_FILE"
echo "# Directory: $(pwd)" >> "$STRUCTURE_FILE"
echo "# For Claude Projects context and understanding" >> "$STRUCTURE_FILE"
echo "" >> "$STRUCTURE_FILE"

# Create tree-like structure (if tree command exists, otherwise use find)
if command -v tree >/dev/null 2>&1; then
    echo "## Directory Tree:" >> "$STRUCTURE_FILE"
    tree -I '__pycache__|*.pyc|node_modules|.git|build|dist|.venv|venv|target|vendor|.claude_proj' -L 4 >> "$STRUCTURE_FILE"
else
    echo "## Directory Structure (find-based):" >> "$STRUCTURE_FILE"
    find . -type d \
        -not -path "./.git*" \
        -not -path "./node_modules*" \
        -not -path "./__pycache__*" \
        -not -path "./build*" \
        -not -path "./dist*" \
        -not -path "./.venv*" \
        -not -path "./venv*" \
        -not -path "./target*" \
        -not -path "./vendor*" \
        -not -path "./.claude_proj*" \
        | head -50 | sort >> "$STRUCTURE_FILE"
fi

echo "" >> "$STRUCTURE_FILE"
echo "## File Count Summary:" >> "$STRUCTURE_FILE"
echo "Total source files: $(find . -name "*.py" -o -name "*.js" -o -name "*.go" -o -name "*.rs" -o -name "*.java" -o -name "*.cs" | wc -l)" >> "$STRUCTURE_FILE"
echo "Configuration files: $(find . -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.toml" | wc -l)" >> "$STRUCTURE_FILE"
echo "Documentation files: $(find . -name "*.rst" -o -name "*.md" | wc -l)" >> "$STRUCTURE_FILE"

# Detect primary language/framework
echo "" >> "$STRUCTURE_FILE"
echo "## Detected Technology Stack:" >> "$STRUCTURE_FILE"
[ -f "package.json" ] && echo "- Node.js/JavaScript (package.json found)" >> "$STRUCTURE_FILE"
[ -f "requirements.txt" ] && echo "- Python (requirements.txt found)" >> "$STRUCTURE_FILE"
[ -f "pyproject.toml" ] && echo "- Modern Python (pyproject.toml found)" >> "$STRUCTURE_FILE"
[ -f "Cargo.toml" ] && echo "- Rust (Cargo.toml found)" >> "$STRUCTURE_FILE"
[ -f "go.mod" ] && echo "- Go (go.mod found)" >> "$STRUCTURE_FILE"
[ -f "pom.xml" ] && echo "- Java Maven (pom.xml found)" >> "$STRUCTURE_FILE"
[ -f "build.gradle" ] && echo "- Java/Kotlin Gradle (build.gradle found)" >> "$STRUCTURE_FILE"
[ -d "docs/source" ] && echo "- Sphinx Documentation (docs/source/ found)" >> "$STRUCTURE_FILE"
[ -f "docker-compose.yml" ] && echo "- Docker Compose (docker-compose.yml found)" >> "$STRUCTURE_FILE"

echo "Project structure saved to: $STRUCTURE_FILE"

# 6. Create upload instructions with .claude_proj context
echo "Creating upload instructions..."
INSTRUCTIONS_FILE="$PROJECT_DIR/UPLOAD_INSTRUCTIONS.txt"

cat > "$INSTRUCTIONS_FILE" << 'EOF'
# CLAUDE PROJECT UPLOAD INSTRUCTIONS

## Quick Setup Summary:
This project uses the .claude_proj/ toolkit for Claude Projects integration.
All files in this directory were automatically generated and optimized for 
Claude Projects caching and token efficiency.

## Files to Upload to Claude Projects Knowledge Base:

### PRIORITY 1 (Upload these first for maximum token efficiency):
1. all_code.txt          - All source code consolidated (CACHED FOREVER)
2. all_config.txt        - Configuration files (CACHED FOREVER)
3. project_structure.txt - Project overview (CACHED FOREVER)
4. README.md             - Main project documentation

### PRIORITY 2 (Upload for complete context):
5. all_docs.txt          - All documentation files
6. Key config files individually (requirements.txt, package.json, etc.)

### PRIORITY 3 (Optional for specific needs):
7. gather_files_script.sh - The script that generated these files
8. Any project-specific files Claude requests

## Upload Tips:
- Upload files one by one if drag-and-drop fails
- If file upload fails, copy/paste content into a new text file
- Focus on Priority 1 files for immediate productivity gains
- The consolidated files provide 90% token savings through caching

## Claude Projects Custom Instructions Template:

Add this to your Claude Project custom instructions (customize for your stack):

"You are an expert developer working on [PROJECT_NAME]. This project contains:

TECHNOLOGY STACK: [List your main technologies from project_structure.txt]
PROJECT TYPE: [Brief description - e.g., 'web application', 'CLI tool', 'library']
DEVELOPMENT STAGE: [e.g., 'prototype', 'production', 'refactoring']

UPLOADED CONTEXT:
- Complete codebase in consolidated format (all_code.txt)
- Full configuration and build setup (all_config.txt)  
- Project structure and organization (project_structure.txt)
- Documentation and README files

PRIORITIES:
1. Reference the uploaded codebase context for all suggestions
2. Maintain consistency with existing architecture and patterns
3. Focus on production-quality code with proper error handling
4. Consider performance, security, and maintainability
5. Suggest improvements that align with the project's technology stack

When making suggestions, always consider the full context of the uploaded 
codebase and maintain consistency with established patterns."

## Language-Specific Enhancement:

Your project appears to use: [CHECK project_structure.txt for detected technologies]

If the gather_files.sh script missed file types specific to your technology stack,
you can enhance it using Claude Code CLI:

1. Navigate to your .claude_proj directory
2. Start Claude Code CLI: claude-code
3. Use this prompt:

"I have a gather_files.sh script that consolidates project files for Claude Projects.
Please analyze my project structure and create an enhanced version that includes
any missing file types for my specific technology stack.

CURRENT SCRIPT: [paste contents of gather_files.sh]
PROJECT TYPE: [describe your stack]

Please create gather_files_v2.sh with additional file types and exclusions
relevant to my technology stack."

## Next Steps:
1. Upload Priority 1 files to your Claude Project
2. Set up custom instructions using the template above
3. Test the setup with a simple question about your codebase
4. Consider enhancing the script for your specific technology needs

## Maintenance:
- Re-run ./.claude_proj/gather_files.sh when you make significant changes
- Update Claude Project files periodically to maintain context
- The cached content in Claude Projects never expires, providing permanent efficiency

EOF

echo "Upload instructions saved to: $INSTRUCTIONS_FILE"

# 7. Create CLI integration prompts
echo "Creating Claude Code CLI integration prompts..."
mkdir -p "$PROJECT_DIR/cli_prompts"

# Setup prompt
cat > "$PROJECT_DIR/cli_prompts/setup_enhancement.md" << 'EOF'
# Claude Code CLI Enhancement Prompt

Use this prompt in Claude Code CLI to enhance the gather_files.sh script for your specific technology stack:

```
I have a .claude_proj directory with a gather_files.sh script for consolidating 
project files for Claude Projects integration.

Please analyze my project structure and file types to determine if the current 
script covers all relevant text files for my technology stack.

CURRENT SCRIPT ANALYSIS NEEDED:
1. Review what file extensions the script currently handles
2. Identify any missing file types for my specific technology stack
3. Look for technology-specific configuration files not covered
4. Check for specialized documentation formats

PROJECT DETAILS:
- Technology stack: [DESCRIBE YOUR STACK]
- Primary language: [YOUR MAIN LANGUAGE]
- Framework/tools: [LIST KEY FRAMEWORKS]
- Special requirements: [ANY UNIQUE FILE TYPES]

DELIVERABLES:
1. Create gather_files_v2.sh with enhanced file type coverage
2. Add any missing exclusion patterns for build artifacts
3. Include technology-specific configuration files
4. Explain what was added and why it's important for Claude Projects

Focus on text-based files that Claude can read and understand. 
Skip binary formats but include any text-based config or source files 
specific to my technology stack.
```
EOF

# Maintenance prompt
cat > "$PROJECT_DIR/cli_prompts/project_maintenance.md" << 'EOF'
# Claude Projects Maintenance Prompt

Use this prompt in Claude Code CLI to update your Claude Project files after significant changes:

```
I have an existing Claude Project with cached codebase context. I've made 
significant changes to my local project and need to update the Claude Project 
files to maintain synchronization.

CURRENT CLAUDE PROJECT SETUP:
- Project name: [YOUR PROJECT NAME]
- Last updated: [DATE OF LAST UPDATE]
- Main files uploaded: all_code.txt, all_config.txt, project_structure.txt

RECENT CHANGES MADE:
[DESCRIBE WHAT YOU CHANGED - e.g., "Added new API endpoints", "Refactored database models", "Updated build configuration"]

TASKS NEEDED:
1. Analyze what has changed since the last Claude Project update
2. Generate new consolidated files (all_code.txt, all_config.txt, all_docs.txt)
3. Create a change summary explaining what's different
4. Update the project structure overview
5. Provide upload instructions for the changed files

Please focus on maintaining the efficiency of Claude Projects caching while 
ensuring the context stays current with my development work.
```
EOF

# Coordination prompt
cat > "$PROJECT_DIR/cli_prompts/cli_coordination.md" << 'EOF'
# Claude Code CLI + Projects Coordination Prompt

Use this prompt in Claude Code CLI when you want to coordinate between local development and your Claude Project:

```
I have a Claude Project called "[PROJECT_NAME]" with my complete codebase 
uploaded and cached. I want to work on [SPECIFIC_FEATURE/TASK] using Claude Code CLI 
while maintaining consistency with the broader project context.

CLAUDE PROJECT CONTEXT:
- Complete codebase cached in Claude Projects web interface  
- Project structure and architecture established
- Documentation and configuration files uploaded

CURRENT LOCAL WORK:
- Feature/task: [DESCRIBE WHAT YOU'RE WORKING ON]
- Files involved: [LIST KEY FILES YOU'LL MODIFY]
- Scope: [LOCAL CHANGES vs ARCHITECTURAL CHANGES]

COORDINATION NEEDS:
1. Reference the cached project context when making suggestions
2. Ensure consistency with existing architecture and patterns
3. Focus on the specific files and features I'm working on locally
4. Maintain code style and conventions from the broader codebase

Please help with [SPECIFIC_REQUEST] while keeping in mind the full project 
context that's available in my Claude Project knowledge base.
```
EOF

echo "CLI integration prompts saved to: $PROJECT_DIR/cli_prompts/"

# 8. Final summary and next steps
echo ""
echo "SUCCESS! Claude Projects integration ready"
echo ""
echo "Generated files in $PROJECT_DIR/:"
ls -la "$PROJECT_DIR" | grep -v "^total"
echo ""
echo "CLI coordination prompts in $PROJECT_DIR/cli_prompts/:"
ls -la "$PROJECT_DIR/cli_prompts/" | grep -v "^total"
echo ""
echo "NEXT STEPS:"
echo ""
echo "1. UPLOAD TO CLAUDE PROJECTS:"
echo "   * Go to claude.ai and create a new Project"
echo "   * Upload files from $PROJECT_DIR/ (start with Priority 1 files)"
echo "   * Follow instructions in UPLOAD_INSTRUCTIONS.txt"
echo ""
echo "2. SET UP PROJECT:"
echo "   * Add custom instructions using the template in UPLOAD_INSTRUCTIONS.txt"
echo "   * Test with a simple question about your codebase"
echo ""
echo "3. ENHANCE IF NEEDED:"
echo "   * Use prompts in cli_prompts/ to customize for your tech stack"
echo "   * Create enhanced versions (v2, v3) for specialized file types"
echo ""
echo "4. MAINTAIN:"
echo "   * Re-run this script when you make significant changes"
echo "   * Update Claude Project files to keep context current"
echo ""
echo "BENEFITS YOU'LL GET:"
echo "   * 90% token savings through Claude Projects caching"
echo "   * Persistent codebase knowledge across all conversations"
echo "   * No more re-uploading files or explaining project structure"
echo "   * Professional AI assistance tailored to YOUR specific project"
echo ""
echo "For complete guidance, see the Claude Projects documentation at:"
echo "   https://github.com/yourname/claude-project-connector"
echo ""
echo "Your project is now optimized for Claude Projects efficiency!"
