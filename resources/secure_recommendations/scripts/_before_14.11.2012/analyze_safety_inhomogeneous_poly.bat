@echo off
Setlocal EnableDelayedExpansion

REM Set folders
set TRAINING_FILES_DIR=D:\mtodor\Desktop\training_test\data\training\safety\

REM Set parameters
set CROSS_VALIDATION_FOLD=10

echo. & echo. & echo %DATE% %TIME% Starting safety SVMs analysis & echo.
echo Output format: "Accuracy|Precision|Recall|F-score|BAC|AUC|AvgNumSVs|filename|Gamma|C" & echo. & echo.
REM Call the main function for each file and combination of parameters
for %%f in (%TRAINING_FILES_DIR%*.train) do (
	REM default weights
	set WEIGHT_ONE=1
	set WEIGHT_MINUS_ONE=1
	
	for %%g in (8, 4, 2, 1, 0.5, 0.125, 0.03125, 0.0078125, 0.001953125, 0.00048828125, 0.0001220703125) do (
		for %%c in (0.0078125, 0.03125, 0.125, 0.5, 1, 2, 4, 8) do (
			call:main %%~pf, %%~nxf, %%g, %%c, !WEIGHT_ONE!, !WEIGHT_MINUS_ONE!
		)
	)
)
echo. & echo. & echo %DATE% %TIME% Finished safety SVMs analysis. & echo. & echo.

echo. & pause & goto:eof

REM Function takes 6 parameters: PATH (to file), FILE (name.extension), GAMMA, C (regularization), WEIGHT_ONE (w1), WEIGHT_MINUS_ONE (w-1)
:main
	set PATH=%~1
	REM echo. & echo. & echo Using PATH: %PATH% & echo. & echo.
	
	set FILE=%~2
	REM echo. & echo. & echo Using FILE: %FILE% & echo. & echo.

	set GAMMA=%~3
	REM echo. & echo. & echo Using GAMMA: %GAMMA% & echo. & echo.

	set C=%~4
	REM echo. & echo. & echo Using C: %C% & echo. & echo.
	
	set WEIGHT_ONE=%~5
	REM echo. & echo. & echo Using w1: %WEIGHT_ONE% & echo. & echo.
	
	set WEIGHT_MINUS_ONE=%~6
	REM echo. & echo. & echo Using w-1: %WEIGHT_MINUS_ONE% & echo. & echo.
	
	svm-train -q -v %CROSS_VALIDATION_FOLD% -t 1 -d 2 -r 1 -g %GAMMA% -c %C% -w1 %WEIGHT_ONE% -w-1 %WEIGHT_MINUS_ONE% %PATH%%FILE%
	echo ^|%FILE%^|%GAMMA%^|%C%

goto:eof