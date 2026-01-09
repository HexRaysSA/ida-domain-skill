# Master Makefile for IDA Domain Scripting Exercises
# Builds all Zig (and C++) binaries for the exercises

.PHONY: all clean help status \
	01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20

# Exercises with Makefiles in src/
SRC_EXERCISES = 01 02 03 05 07 13 17 19

# Exercises with Makefiles in root
ROOT_EXERCISES = 04 06 08 09 12 16 18

# C++ exercise (in src/)
CPP_EXERCISES = 11

# Skipped exercises (no buildable source)
SKIPPED = 10 14 15 20

# All buildable exercises
ALL_EXERCISES = $(SRC_EXERCISES) $(ROOT_EXERCISES) $(CPP_EXERCISES)

# Default target
all: $(ALL_EXERCISES)
	@echo ""
	@echo "=========================================="
	@echo "Build complete!"
	@echo "=========================================="
	@$(MAKE) --no-print-directory status

# Individual exercise targets - src/ Makefiles
01:
	@echo "Building 01_auto_tag_function_roles..."
	@$(MAKE) -C 01_auto_tag_function_roles/src --no-print-directory || echo "  [FAILED]"

02:
	@echo "Building 02_callgraph_hotspot_ranking..."
	@$(MAKE) -C 02_callgraph_hotspot_ranking/src --no-print-directory || echo "  [FAILED]"

03:
	@echo "Building 03_thunk_forest_deobfuscation..."
	@$(MAKE) -C 03_thunk_forest_deobfuscation/src --no-print-directory || echo "  [FAILED]"

05:
	@echo "Building 05_encrypted_string_recovery..."
	@$(MAKE) -C 05_encrypted_string_recovery/src --no-print-directory || echo "  [FAILED]"

07:
	@echo "Building 07_string_provenance_report..."
	@$(MAKE) -C 07_string_provenance_report/src --no-print-directory || echo "  [FAILED]"

13:
	@echo "Building 13_flattening_detection..."
	@$(MAKE) -C 13_flattening_detection/src --no-print-directory || echo "  [FAILED]"

17:
	@echo "Building 17_hook_surface_identification..."
	@$(MAKE) -C 17_hook_surface_identification/src --no-print-directory || echo "  [FAILED]"

19:
	@echo "Building 19_symbolic_constant_propagation..."
	@$(MAKE) -C 19_symbolic_constant_propagation/src --no-print-directory || echo "  [FAILED]"

# Individual exercise targets - root Makefiles
04:
	@echo "Building 04_cross_module_import_map..."
	@$(MAKE) -C 04_cross_module_import_map --no-print-directory || echo "  [FAILED]"

06:
	@echo "Building 06_config_structure_carving..."
	@$(MAKE) -C 06_config_structure_carving --no-print-directory || echo "  [FAILED]"

08:
	@echo "Building 08_command_table_dispatch..."
	@$(MAKE) -C 08_command_table_dispatch --no-print-directory || echo "  [FAILED]"

09:
	@echo "Building 09_prototype_reconstruction..."
	@$(MAKE) -C 09_prototype_reconstruction --no-print-directory || echo "  [FAILED]"

12:
	@echo "Building 12_decompiler_renaming..."
	@$(MAKE) -C 12_decompiler_renaming --no-print-directory || echo "  [FAILED]"

16:
	@echo "Building 16_auth_license_check_finder..."
	@$(MAKE) -C 16_auth_license_check_finder --no-print-directory || echo "  [FAILED]"

18:
	@echo "Building 18_binary_sarif_export..."
	@$(MAKE) -C 18_binary_sarif_export --no-print-directory || echo "  [FAILED]"

# C++ exercise
11:
	@echo "Building 11_vtable_discovery (C++)..."
	@$(MAKE) -C 11_vtable_discovery/src --no-print-directory || echo "  [FAILED]"

# Skipped exercises - just print info
10:
	@echo "Skipping 10_function_chunk_repair (see SKIP.md)"

14:
	@echo "Skipping 14_opaque_predicate_detection (see SKIP.md)"

15:
	@echo "Skipping 15_junk_block_cleanup (see SKIP.md)"

20:
	@echo "Skipping 20_scalable_project_annotator (see SKIP.md)"

# Clean all builds
clean:
	@echo "Cleaning all exercises..."
	@echo ""
	@# Try sub-Makefile clean targets first
	@for dir in 01_*/src 02_*/src 03_*/src 05_*/src 07_*/src 11_*/src 13_*/src 17_*/src 19_*/src; do \
		if [ -f "$$dir/Makefile" ]; then \
			echo "  Cleaning $$dir..."; \
			$(MAKE) -C "$$dir" clean --no-print-directory 2>/dev/null || true; \
		fi \
	done
	@for dir in 04_* 06_* 08_* 09_* 12_* 16_* 18_*; do \
		if [ -f "$$dir/Makefile" ]; then \
			echo "  Cleaning $$dir..."; \
			$(MAKE) -C "$$dir" clean --no-print-directory 2>/dev/null || true; \
		fi \
	done
	@echo ""
	@# Direct cleanup of common build artifacts
	@echo "  Removing build artifacts..."
	@rm -f */input */src/input 2>/dev/null || true
	@rm -rf */build */src/build 2>/dev/null || true
	@rm -f */*.o */src/*.o 2>/dev/null || true
	@rm -f */*.exe */src/*.exe 2>/dev/null || true
	@rm -f */encrypted_strings* */src/encrypted_strings* 2>/dev/null || true
	@rm -f */thunk_forest */src/thunk_forest 2>/dev/null || true
	@rm -f */vtable_demo */src/vtable_demo 2>/dev/null || true
	@rm -f */vulnerable_app */src/vulnerable_app 2>/dev/null || true
	@rm -rf */.zig-cache */src/.zig-cache 2>/dev/null || true
	@echo ""
	@echo "Clean complete."
	@$(MAKE) --no-print-directory status

# Show build status
status:
	@echo ""
	@echo "Build Status:"
	@echo "============="
	@for ex in 01 02 03 04 05 06 07 08 09 11 12 13 16 17 18 19; do \
		dir=$$(ls -d $${ex}_* 2>/dev/null | head -1); \
		if [ -n "$$dir" ]; then \
			found=0; \
			[ -f "$$dir/input" ] && found=1; \
			[ -f "$$dir/src/input" ] && found=1; \
			[ -d "$$dir/build" ] && [ "$$(ls -A $$dir/build 2>/dev/null)" ] && found=1; \
			[ -d "$$dir/src/build" ] && [ "$$(ls -A $$dir/src/build 2>/dev/null)" ] && found=1; \
			if [ $$found -eq 1 ]; then \
				printf "  [OK]     %s\n" "$$dir"; \
			else \
				printf "  [--]     %s\n" "$$dir"; \
			fi \
		fi \
	done
	@echo ""
	@echo "Skipped (see SKIP.md in each folder):"
	@for ex in 10 14 15 20; do \
		dir=$$(ls -d $${ex}_* 2>/dev/null | head -1); \
		if [ -n "$$dir" ]; then \
			printf "  [SKIP]   %s\n" "$$dir"; \
		fi \
	done

# Help
help:
	@echo "IDA Domain Scripting Exercises - Build System"
	@echo ""
	@echo "Usage:"
	@echo "  make          Build all exercises"
	@echo "  make XX       Build exercise XX (e.g., make 01, make 05)"
	@echo "  make clean    Clean all build artifacts"
	@echo "  make status   Show build status for all exercises"
	@echo "  make help     Show this help"
	@echo ""
	@echo "Buildable exercises: $(ALL_EXERCISES)"
	@echo "Skipped exercises:   $(SKIPPED)"
	@echo ""
	@echo "Requirements:"
	@echo "  - Zig 0.11+ (for most exercises)"
	@echo "  - Clang/GCC (for exercise 11 - C++)"
