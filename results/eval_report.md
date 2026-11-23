# Evaluation report

Operating points: **flag** (verdict suspicious or malicious) at score >= 0.35, **block** (verdict malicious) at score >= 0.6. Intervals are 95% Wilson.

## Synthetic corpus, rule set v1

| split | flagged | blocked |
|---|---|---|
| dev | 100% (48/48) [93%-100%] | 85% (41/48) [73%-93%] |
| heldout | 100% (20/20) [84%-100%] | 75% (15/20) [53%-89%] |
| adaptive | 11% (3/27) [4%-28%] | 0% (0/27) [0%-12%] |
| benign hard negatives (false positives) | 5% (2/38) [1%-17%] | 5% (2/38) [1%-17%] |

| family | flagged | blocked |
|---|---|---|
| dev/d1_setup_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d2_b64_stage_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d3_npm_postinstall_download_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d4_npm_postinstall_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d5_typosquat_cred_stealer | 100% (6/6) [61%-100%] | 83% (5/6) [44%-97%] |
| dev/d6_npm_webhook_stealer | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d7_pypi_pth_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d8_dependency_confusion | 100% (6/6) [61%-100%] | 0% (0/6) [0%-39%] |
| heldout/h1_npm_obfuscator_io | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h2_pypi_multistage_zlib | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h3_npm_persistence | 100% (5/5) [57%-100%] | 0% (0/5) [0%-43%] |
| heldout/h4_pypi_ci_gated | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| adaptive/a1_getattr_dispatch | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a2_split_across_files | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a3_chr_join_command | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a4_delayed_trigger | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| adaptive/a5_payload_in_data_file | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a6_js_split_require | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a7_py_selective_env_keys | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a8_js_selective_env_keys | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a9_path_join_credentials | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| benign/plain_math | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/b64_utils | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/http_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/env_config | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/expr_eval | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/proc_runner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cred_reader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/readme_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/nspkg_pth | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_scanner_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/embedded_asset | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/update_check | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/plugin_loader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/gh_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/template_data | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/vendored_build | 100% (2/2) [34%-100%] | 100% (2/2) [34%-100%] |
| benign/util_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/postinstall_banner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_addon | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/husky_prepare | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/api_wrapper | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cli_tool | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_fixtures_js | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/dyn_require | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |

Benign synthetic families that were flagged: vendored_build


## Synthetic corpus, rule set v2

| split | flagged | blocked |
|---|---|---|
| dev | 100% (48/48) [93%-100%] | 85% (41/48) [73%-93%] |
| heldout | 100% (20/20) [84%-100%] | 75% (15/20) [53%-89%] |
| adaptive | 89% (24/27) [72%-96%] | 67% (18/27) [48%-81%] |
| benign hard negatives (false positives) | 5% (2/38) [1%-17%] | 5% (2/38) [1%-17%] |

| family | flagged | blocked |
|---|---|---|
| dev/d1_setup_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d2_b64_stage_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d3_npm_postinstall_download_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d4_npm_postinstall_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d5_typosquat_cred_stealer | 100% (6/6) [61%-100%] | 83% (5/6) [44%-97%] |
| dev/d6_npm_webhook_stealer | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d7_pypi_pth_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d8_dependency_confusion | 100% (6/6) [61%-100%] | 0% (0/6) [0%-39%] |
| heldout/h1_npm_obfuscator_io | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h2_pypi_multistage_zlib | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h3_npm_persistence | 100% (5/5) [57%-100%] | 0% (0/5) [0%-43%] |
| heldout/h4_pypi_ci_gated | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| adaptive/a1_getattr_dispatch | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a2_split_across_files | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a3_chr_join_command | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a4_delayed_trigger | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| adaptive/a5_payload_in_data_file | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a6_js_split_require | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a7_py_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a8_js_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a9_path_join_credentials | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| benign/plain_math | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/b64_utils | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/http_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/env_config | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/expr_eval | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/proc_runner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cred_reader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/readme_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/nspkg_pth | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_scanner_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/embedded_asset | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/update_check | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/plugin_loader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/gh_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/template_data | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/vendored_build | 100% (2/2) [34%-100%] | 100% (2/2) [34%-100%] |
| benign/util_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/postinstall_banner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_addon | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/husky_prepare | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/api_wrapper | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cli_tool | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_fixtures_js | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/dyn_require | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |

Benign synthetic families that were flagged: vendored_build


## Synthetic corpus, rule set v3

| split | flagged | blocked |
|---|---|---|
| dev | 100% (48/48) [93%-100%] | 85% (41/48) [73%-93%] |
| heldout | 100% (20/20) [84%-100%] | 75% (15/20) [53%-89%] |
| adaptive | 89% (24/27) [72%-96%] | 67% (18/27) [48%-81%] |
| benign hard negatives (false positives) | 5% (2/38) [1%-17%] | 5% (2/38) [1%-17%] |

| family | flagged | blocked |
|---|---|---|
| dev/d1_setup_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d2_b64_stage_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d3_npm_postinstall_download_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d4_npm_postinstall_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d5_typosquat_cred_stealer | 100% (6/6) [61%-100%] | 83% (5/6) [44%-97%] |
| dev/d6_npm_webhook_stealer | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d7_pypi_pth_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d8_dependency_confusion | 100% (6/6) [61%-100%] | 0% (0/6) [0%-39%] |
| heldout/h1_npm_obfuscator_io | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h2_pypi_multistage_zlib | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h3_npm_persistence | 100% (5/5) [57%-100%] | 0% (0/5) [0%-43%] |
| heldout/h4_pypi_ci_gated | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| adaptive/a1_getattr_dispatch | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a2_split_across_files | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a3_chr_join_command | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a4_delayed_trigger | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| adaptive/a5_payload_in_data_file | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a6_js_split_require | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a7_py_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a8_js_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a9_path_join_credentials | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| benign/plain_math | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/b64_utils | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/http_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/env_config | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/expr_eval | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/proc_runner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cred_reader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/readme_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/nspkg_pth | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_scanner_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/embedded_asset | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/update_check | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/plugin_loader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/gh_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/template_data | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/vendored_build | 100% (2/2) [34%-100%] | 100% (2/2) [34%-100%] |
| benign/util_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/postinstall_banner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_addon | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/husky_prepare | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/api_wrapper | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cli_tool | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_fixtures_js | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/dyn_require | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |

Benign synthetic families that were flagged: vendored_build


## Synthetic corpus, rule set v4

| split | flagged | blocked |
|---|---|---|
| dev | 100% (48/48) [93%-100%] | 85% (41/48) [73%-93%] |
| heldout | 100% (20/20) [84%-100%] | 75% (15/20) [53%-89%] |
| adaptive | 89% (24/27) [72%-96%] | 67% (18/27) [48%-81%] |
| benign hard negatives (false positives) | 5% (2/38) [1%-17%] | 5% (2/38) [1%-17%] |

| family | flagged | blocked |
|---|---|---|
| dev/d1_setup_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d2_b64_stage_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d3_npm_postinstall_download_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d4_npm_postinstall_env_exfil | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d5_typosquat_cred_stealer | 100% (6/6) [61%-100%] | 83% (5/6) [44%-97%] |
| dev/d6_npm_webhook_stealer | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d7_pypi_pth_exec | 100% (6/6) [61%-100%] | 100% (6/6) [61%-100%] |
| dev/d8_dependency_confusion | 100% (6/6) [61%-100%] | 0% (0/6) [0%-39%] |
| heldout/h1_npm_obfuscator_io | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h2_pypi_multistage_zlib | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| heldout/h3_npm_persistence | 100% (5/5) [57%-100%] | 0% (0/5) [0%-43%] |
| heldout/h4_pypi_ci_gated | 100% (5/5) [57%-100%] | 100% (5/5) [57%-100%] |
| adaptive/a1_getattr_dispatch | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a2_split_across_files | 0% (0/3) [0%-56%] | 0% (0/3) [0%-56%] |
| adaptive/a3_chr_join_command | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a4_delayed_trigger | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| adaptive/a5_payload_in_data_file | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a6_js_split_require | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a7_py_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a8_js_selective_env_keys | 100% (3/3) [44%-100%] | 100% (3/3) [44%-100%] |
| adaptive/a9_path_join_credentials | 100% (3/3) [44%-100%] | 0% (0/3) [0%-56%] |
| benign/plain_math | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/b64_utils | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/http_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/env_config | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/expr_eval | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/proc_runner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cred_reader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/readme_setup | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/nspkg_pth | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_scanner_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/embedded_asset | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/update_check | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/plugin_loader | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/gh_client | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/template_data | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/vendored_build | 100% (2/2) [34%-100%] | 100% (2/2) [34%-100%] |
| benign/util_lib | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/postinstall_banner | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/native_addon | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/husky_prepare | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/api_wrapper | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/cli_tool | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/sec_fixtures_js | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |
| benign/dyn_require | 0% (0/2) [0%-66%] | 0% (0/2) [0%-66%] |

Benign synthetic families that were flagged: vendored_build


## Real benign packages (false positives)

A = development sample (inspected while building rules). B = test sample for v1/v2 (and NOT clean for v3: the v3 fixes were designed after seeing B's failures). C = clean for v3 but used to diagnose v4. D = fetched before v4 was frozen and never scanned until the final run: the clean test for v4.

| set / rules | n | flagged | blocked | median s | p95 s |
|---|---|---|---|---|---|
| A_v1 | 287 | 2% (5/287) [1%-4%] | 0% (0/287) [0%-1%] | 0.22 | 5.16 |
| A_v2 | 287 | 2% (6/287) [1%-4%] | 0% (0/287) [0%-1%] | 0.17 | 4.91 |
| A_v3 | 287 | 2% (5/287) [1%-4%] | 0% (0/287) [0%-1%] | 0.19 | 5.31 |
| A_v4 | 287 | 2% (5/287) [1%-4%] | 0% (0/287) [0%-1%] | 0.2 | 5.26 |
| B_v1 | 260 | 1% (2/260) [0%-3%] | 0% (1/260) [0%-2%] | 0.17 | 4.22 |
| B_v2 | 260 | 2% (4/260) [1%-4%] | 0% (1/260) [0%-2%] | 0.12 | 4.33 |
| B_v3 | 260 | 1% (2/260) [0%-3%] | 0% (0/260) [0%-1%] | 0.16 | 4.31 |
| B_v4 | 260 | 1% (2/260) [0%-3%] | 0% (0/260) [0%-1%] | 0.16 | 4.39 |
| C_v1 | 260 | 2% (5/260) [1%-4%] | 1% (3/260) [0%-3%] | 0.42 | 12.3 |
| C_v2 | 260 | 2% (6/260) [1%-5%] | 1% (3/260) [0%-3%] | 0.34 | 11.16 |
| C_v3 | 260 | 2% (6/260) [1%-5%] | 1% (3/260) [0%-3%] | 0.33 | 11.02 |
| C_v4 | 260 | 2% (6/260) [1%-5%] | 1% (3/260) [0%-3%] | 0.39 | 11.0 |
| D_v1 | 260 | 4% (11/260) [2%-7%] | 2% (4/260) [1%-4%] | 0.56 | 14.16 |
| D_v2 | 260 | 5% (12/260) [3%-8%] | 2% (5/260) [1%-4%] | 0.56 | 14.94 |
| D_v3 | 260 | 4% (11/260) [2%-7%] | 1% (3/260) [0%-3%] | 0.59 | 14.89 |
| D_v4 | 260 | 4% (11/260) [2%-7%] | 1% (3/260) [0%-3%] | 0.63 | 16.88 |

Flagged in A_v1:

- ipython (pypi) 0.5 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- coloredlogs (pypi) 0.47 suspicious: PTH-EXEC-LINE, YARA-MPD_pth_executable_line
- spacy (pypi) 0.43 suspicious: PY-EXEC-DYNAMIC, PY-SHELL-EXEC, IOC-ABUSE-INFRA-RAW-HOSTING
- babel (pypi) 0.42 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-SHELL-EXEC
- execnet (pypi) 0.38 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC

Flagged in A_v2:

- mlflow (pypi) 0.55 suspicious: PY-EXFIL, PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING
- ipython (pypi) 0.53 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- coloredlogs (pypi) 0.47 suspicious: PTH-EXEC-LINE, YARA-MPD_pth_executable_line
- spacy (pypi) 0.47 suspicious: PY-EXEC-DYNAMIC, PY-SHELL-EXEC, IOC-ABUSE-INFRA-RAW-HOSTING
- babel (pypi) 0.45 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-SHELL-EXEC
- execnet (pypi) 0.38 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC

Flagged in A_v3:

- mlflow (pypi) 0.55 suspicious: PY-EXFIL, PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING
- coloredlogs (pypi) 0.47 suspicious: PTH-EXEC-LINE, YARA-MPD_pth_executable_line
- ipython (pypi) 0.47 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, IOC-ABUSE-INFRA-RAW-HOSTING
- spacy (pypi) 0.47 suspicious: PY-EXEC-DYNAMIC, PY-SHELL-EXEC, IOC-ABUSE-INFRA-RAW-HOSTING
- execnet (pypi) 0.38 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC

Flagged in A_v4:

- mlflow (pypi) 0.55 suspicious: PY-EXFIL, PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING
- coloredlogs (pypi) 0.47 suspicious: PTH-EXEC-LINE, YARA-MPD_pth_executable_line
- ipython (pypi) 0.47 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, IOC-ABUSE-INFRA-RAW-HOSTING
- spacy (pypi) 0.47 suspicious: PY-EXEC-DYNAMIC, PY-SHELL-EXEC, IOC-ABUSE-INFRA-RAW-HOSTING
- execnet (pypi) 0.38 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC

Flagged in B_v1:

- mypy (pypi) 0.67 malicious: PY-EXEC-DECODED, PY-SHELL-EXEC, PY-SHELL-EXEC
- pycryptodomex (pypi) 0.51 suspicious: PKG-TYPOSQUAT, PY-EXEC-DYNAMIC

Flagged in B_v2:

- mypy (pypi) 0.71 malicious: PY-EXEC-DECODED, PY-SHELL-EXEC, PY-DYN-IMPORT
- pycryptodomex (pypi) 0.57 suspicious: PKG-TYPOSQUAT, PY-EXEC-DYNAMIC, PY-DYN-IMPORT
- ghapi (pypi) 0.47 suspicious: PY-EXFIL, OBF-ENCODED-PAYLOAD, OBF-ENCODED-PAYLOAD
- kubernetes (pypi) 0.38 suspicious: PY-EXEC-DECODED, PY-DYN-IMPORT, PY-DYN-IMPORT

Flagged in B_v3:

- pycryptodomex (pypi) 0.57 suspicious: PKG-TYPOSQUAT, PY-EXEC-DYNAMIC, PY-DYN-IMPORT
- ghapi (pypi) 0.47 suspicious: PY-EXFIL, OBF-ENCODED-PAYLOAD, OBF-ENCODED-PAYLOAD

Flagged in B_v4:

- pycryptodomex (pypi) 0.57 suspicious: PKG-TYPOSQUAT, PY-EXEC-DYNAMIC, PY-DYN-IMPORT
- ghapi (pypi) 0.47 suspicious: PY-EXFIL, OBF-ENCODED-PAYLOAD, OBF-ENCODED-PAYLOAD

Flagged in C_v1:

- dprint (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- bun (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- prisma (npm) 0.6 malicious: JS-FETCH-AND-RUN, JS-BEACON
- sympy (pypi) 0.46 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- llvmlite (pypi) 0.39 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC, PY-SHELL-EXEC

Flagged in C_v2:

- dprint (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- bun (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- prisma (npm) 0.6 malicious: JS-FETCH-AND-RUN, JS-BEACON
- sympy (pypi) 0.53 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- llvmlite (pypi) 0.39 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC, PY-SHELL-EXEC
- jupyter-builder (pypi) 0.35 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, PY-DYN-IMPORT

Flagged in C_v3:

- dprint (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- bun (npm) 0.68 malicious: JS-FETCH-AND-RUN, JS-CHILD-PROCESS, NPM-LIFECYCLE-SCRIPT
- prisma (npm) 0.6 malicious: JS-FETCH-AND-RUN, JS-BEACON
- sympy (pypi) 0.49 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- llvmlite (pypi) 0.37 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- jupyter-builder (pypi) 0.35 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, PY-DYN-IMPORT

Flagged in C_v4:

- dprint (npm) 0.77 malicious: JS-FETCH-AND-RUN, JS-BEACON, JS-CHILD-PROCESS
- bun (npm) 0.77 malicious: JS-FETCH-AND-RUN, JS-BEACON, JS-CHILD-PROCESS
- prisma (npm) 0.6 malicious: JS-FETCH-AND-RUN, JS-BEACON
- sympy (pypi) 0.49 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- llvmlite (pypi) 0.37 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- jupyter-builder (pypi) 0.35 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, PY-DYN-IMPORT

Flagged in D_v1:

- reportlab (pypi) 0.78 malicious: PY-FETCH-AND-RUN-FILE, PY-EXEC-DYNAMIC, PY-SHELL-EXEC
- mcp-remote (npm) 0.67 malicious: JS-FETCH-AND-RUN, JS-BEACON, SCAN-ANALYZER-ERROR
- setuptools (pypi) 0.63 malicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- pydeck (pypi) 0.6 malicious: PY-EXEC-DYNAMIC, PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- poetry-core (pypi) 0.54 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- debugpy (pypi) 0.46 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- hatchling (pypi) 0.45 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- gcsfs (pypi) 0.43 suspicious: SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC
- xgboost (pypi) 0.39 suspicious: PY-EXFIL, PY-PERSISTENCE
- omegaconf (pypi) 0.37 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- ipykernel (pypi) 0.37 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC

Flagged in D_v2:

- reportlab (pypi) 0.79 malicious: PY-FETCH-AND-RUN-FILE, PY-EXEC-DYNAMIC, PY-SHELL-EXEC
- mcp-remote (npm) 0.67 malicious: JS-FETCH-AND-RUN, JS-BEACON, SCAN-ANALYZER-ERROR
- setuptools (pypi) 0.66 malicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- debugpy (pypi) 0.61 malicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- pydeck (pypi) 0.6 malicious: PY-EXEC-DYNAMIC, PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- omegaconf (pypi) 0.57 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-EXFIL, PY-SHELL-EXEC
- poetry-core (pypi) 0.54 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- hatchling (pypi) 0.45 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- gcsfs (pypi) 0.43 suspicious: SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC
- xgboost (pypi) 0.39 suspicious: PY-EXFIL, PY-PERSISTENCE
- ipykernel (pypi) 0.37 suspicious: PY-EXEC-DECODED, PY-EXEC-DYNAMIC
- uv (pypi) 0.36 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, IOC-ABUSE-INFRA-RAW-HOSTING

Flagged in D_v3:

- reportlab (pypi) 0.79 malicious: PY-FETCH-AND-RUN-FILE, PY-EXEC-DYNAMIC, PY-SHELL-EXEC
- mcp-remote (npm) 0.67 malicious: JS-FETCH-AND-RUN, JS-BEACON, SCAN-ANALYZER-ERROR
- pydeck (pypi) 0.6 malicious: PY-EXEC-DYNAMIC, PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- poetry-core (pypi) 0.54 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- omegaconf (pypi) 0.52 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-EXFIL, PY-DYN-IMPORT
- setuptools (pypi) 0.45 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PYPI-INTREE-BACKEND, PY-EXEC-DYNAMIC
- hatchling (pypi) 0.45 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- gcsfs (pypi) 0.43 suspicious: SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC
- xgboost (pypi) 0.39 suspicious: PY-EXFIL, PY-PERSISTENCE
- debugpy (pypi) 0.38 suspicious: PY-OBFUSCATED-CALL, PY-SHELL-EXEC, PY-DYN-IMPORT
- uv (pypi) 0.36 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, IOC-ABUSE-INFRA-RAW-HOSTING

Flagged in D_v4:

- reportlab (pypi) 0.85 malicious: PY-FETCH-AND-RUN-FILE, PY-BEACON-FILE, PY-EXEC-DYNAMIC
- mcp-remote (npm) 0.67 malicious: JS-FETCH-AND-RUN, JS-BEACON, SCAN-ANALYZER-ERROR
- pydeck (pypi) 0.6 malicious: PY-EXEC-DYNAMIC, PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-SHELL-EXEC
- poetry-core (pypi) 0.54 suspicious: PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC, PY-EXEC-DYNAMIC
- omegaconf (pypi) 0.52 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PY-EXFIL, PY-DYN-IMPORT
- setuptools (pypi) 0.45 suspicious: PYPI-CMDCLASS-INSTALL-OVERRIDE, PYPI-INTREE-BACKEND, PY-EXEC-DYNAMIC
- hatchling (pypi) 0.45 suspicious: PY-EXEC-DYNAMIC, PYPI-INTREE-BACKEND, PY-SHELL-EXEC
- gcsfs (pypi) 0.43 suspicious: SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC, SH-DOWNLOAD-EXEC
- xgboost (pypi) 0.39 suspicious: PY-EXFIL, PY-PERSISTENCE
- debugpy (pypi) 0.38 suspicious: PY-OBFUSCATED-CALL, PY-SHELL-EXEC, PY-DYN-IMPORT
- uv (pypi) 0.36 suspicious: PY-EXFIL, IOC-ABUSE-INFRA-RAW-HOSTING, IOC-ABUSE-INFRA-RAW-HOSTING

## Threshold calibrated on set A at 1% FPR (v1)

threshold = 0.468
- FPR on A: 1% (2/287) [0%-2%]
- FPR on B: 1% (2/260) [0%-3%]
- FPR on C: 1% (3/260) [0%-3%]
- FPR on D (fresh, never seen before the final run): 2% (5/260) [1%-4%]
- synthetic malicious detected: 69% (66/95) [60%-78%]
- AUC, synthetic malicious vs real B benign: 0.9211

## Threshold calibrated on set A at 1% FPR (v2)

threshold = 0.533
- FPR on A: 1% (2/287) [0%-2%]
- FPR on B: 1% (2/260) [0%-3%]
- FPR on C: 1% (3/260) [0%-3%]
- FPR on D (fresh, never seen before the final run): 3% (7/260) [1%-5%]
- synthetic malicious detected: 81% (77/95) [72%-88%]
- AUC, synthetic malicious vs real B benign: 0.9902

## Threshold calibrated on set A at 1% FPR (v3)

threshold = 0.468
- FPR on A: 1% (2/287) [0%-2%]
- FPR on B: 0% (1/260) [0%-2%]
- FPR on C: 2% (4/260) [1%-4%]
- FPR on D (fresh, never seen before the final run): 2% (5/260) [1%-4%]
- synthetic malicious detected: 92% (87/95) [84%-96%]
- AUC, synthetic malicious vs real B benign: 0.992

## Threshold calibrated on set A at 1% FPR (v4)

threshold = 0.468
- FPR on A: 1% (2/287) [0%-2%]
- FPR on B: 0% (1/260) [0%-2%]
- FPR on C: 2% (4/260) [1%-4%]
- FPR on D (fresh, never seen before the final run): 2% (5/260) [1%-4%]
- synthetic malicious detected: 92% (87/95) [84%-96%]
- AUC, synthetic malicious vs real B benign: 0.992

## Ablation (rule set v2, synthetic corpus)

Baseline flags 92/95 malicious samples.

| analyzer group switched off | malicious flagged | change | hard negatives flagged |
|---|---|---|---|
| blobs | 92/95 | +0 | 2 |
| hooks | 47/95 | -45 | 0 |
| infra | 92/95 | +0 | 2 |
| js | 76/95 | -16 | 2 |
| metadata | 89/95 | -3 | 2 |
| python | 55/95 | -37 | 0 |
| shell | 80/95 | -12 | 2 |
| typosquat | 92/95 | +0 | 2 |
| yara | 92/95 | +0 | 2 |
