# Contributing to Linux Security Hardening Tool

Thank you for your interest in contributing to this project! We welcome contributions that help improve the security hardening capabilities of this tool.

## Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Ensure your code follows the style guide
5. Add tests for any new functionality
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a pull request

## Code Style Guidelines

- Follow PEP 8 for Python code style
- Use descriptive variable and function names
- Include docstrings for all functions and classes
- Comment complex logic where necessary
- Keep functions focused on a single responsibility

## Testing Requirements

Before submitting your changes:
1. Run the tool on different Linux distributions (if possible)
2. Verify no regressions in existing functionality
3. Ensure all interactive prompts work correctly
4. Check that automatic mode still functions as expected
5. Validate that logging works correctly

## Security Considerations

- Never include hardcoded credentials
- Validate all input parameters
- Use appropriate permissions for created files
- Avoid executing untrusted commands
- Consider edge cases that could be exploited

## Documentation Updates

When adding new features, please update:
- README.md with any new features or usage examples
- Command-line help text for new options
- Any relevant documentation files

## Issue Reporting

When reporting issues:
1. Include the Linux distribution and version
2. Provide the exact command used
3. Share relevant log output (redacting sensitive information)
4. Describe the expected vs. actual behavior
5. Include steps to reproduce the issue

## Code Review Process

All submissions will be reviewed by maintainers focusing on:
- Security implications
- Code quality and maintainability
- Performance impact
- Distribution compatibility
- User experience considerations

## Questions?

If you have any questions about contributing, please open an issue with the "question" label.

Thank you for helping make this tool more secure and useful for everyone!
