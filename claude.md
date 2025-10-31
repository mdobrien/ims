## Kickstart

This project follows a strict **build-test-repeat** pattern where:
- Each phase delivers a working, testable increment
- No phase begins until the previous phase is fully tested and validated
- Every build step is immediately followed by comprehensive testing
- We maintain a healthy balance between building new features and validating existing ones

**Premature optimization and complexity is highly undesirable.**


### Stric Rules for debugging

Take a step back and slow down. Isolate the root cause. Do not make code changes other then adding logs or
writing debug tests in scratch. Identidy the root cause. Then implement the fix. create an issue in scratch/issues. This should be continuously updated throughout the debugging process. The issue is the central place for information validation results, fix summaries, list of test files created during debuging.

    📊 Success Criteria

    After running diagnostics, we will have:
    1. ✅ Clear evidence of EXACTLY where the failure occurs
    2. ✅ Logs showing daemon startup sequence
    3. ✅ Confirmation of which hypothesis is correct
    4. ✅ Specific fix identified (not guessed)

    🚫 What We Will NOT Do

    - ❌ Make code changes before understanding root cause
    - ❌ Try multiple fixes hoping one works
    - ❌ Add more complexity without evidence
    - ❌ Assume anything without checking

I want a well-designed prototype. Do not perceive my aversion to premature complexity as a desire for sloppy code—I value clean, maintainable code that serves the core purpose without over-engineering.

### Avoid
- Premature abstractions
- Over-engineered architecture
- Features not essential to the core value proposition
- Complex dependencies when simpler alternatives exist
- Optimization before identifying actual bottlenecks


### UI development
Use vanilla javascript and CSS for UIs. I don't want complexity here until i have follow defined user work flows and have an end to end application working. Then we can we factor to add frameworks and complexity.


## File Organization

### `/scratch` Directory
Use the `scratch/` directory for:
- One-off scripts that don't have a permanent home
- Debug utilities and diagnostic tools
- Experimental code snippets
- Quick prototypes and proof-of-concepts
- Development helpers that aid debugging

Think of `scratch/` as your development scratchpad—a place for tools that make development easier but aren't part of the core application.

## Code Quality Standards

- Write clear, readable code with descriptive variable names
- Include basic error handling where it matters
- Add comments for business logic, not implementation details
- Keep functions focused on single responsibilities
- Structure code for easy modification, not premature scalability

### Creating network configs for core
- you can't have 3 nodes all on the same link in CORE. Each link connects exactly 2 nodes. Let me create a proper hub-and-spoke topology instead where B is in the middle:
