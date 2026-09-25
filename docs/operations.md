# Conversion operations

The unified workbench reports source validation, parsing, normalization, CP0, CP1, CP2, candidate rendering, semantic diff, findings, finalization, and completion. Analysis-only operations mark candidate rendering as skipped. Elapsed time is transient and never enters project or migration artifacts.

The browser starts an in-process operation and polls `GET /api/operations/{operation_id}`. Operation IDs and timing exist only in memory. A lost polling connection reports that status visibility was lost; it does not claim conversion failure.

`convert_in.operations` emits INFO lifecycle records with project ID, domain, profile IDs, stage, duration, and counts already produced by the operation. ERROR records identify the failed stage and exception class. Logs never include source configuration, configuration lines, object values, credentials, private keys, or rendered candidates. Uvicorn access logging remains enabled.

For a failed operation, inspect the named stage and safe error message in Card 3, then correct the source or profile selection and retry. If progress status is lost, confirm the local Uvicorn process is running, refresh the project, and check the terminal for the last completed stage.