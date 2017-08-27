@echo off
Setlocal EnableDelayedExpansion

REM Set folders
set TrainingBaseDir=D:\mtodor\Desktop\training_test\data\training\
set ModelsBaseDir=D:\mtodor\_Work\Projects\KindredSpirits\_output\x64\MPIRDebug\models\

REM Call the main function for each set of training files

echo. & echo. & echo Training medical relevance SVMs & echo. & echo.
call:create_directories %ModelsBaseDir%medical_relevance\
call:medical_relevance

echo. & echo. & echo Finished training medical relevance SVMs & echo. & echo.

echo. & echo. & echo Training safety SVMs & echo. & echo.
call:create_directories %ModelsBaseDir%safety\
call:safety

echo. & echo. & echo Finished training safety SVMs & echo. & echo.

echo. & pause & goto:eof

:medical_relevance
	
	set CLinear=131072
	set CHomogeneousPoly=8192
	set GammaInhomogeneousPoly=2
	set CInhomogeneousPoly=2048
	set GammaRbf=0.00390625
	set CRbf=8388608
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster1v2, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=4096
	set CHomogeneousPoly=16384
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=2048
	set GammaRbf=0.0078125
	set CRbf=524288
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster1v3, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=4096
	set GammaInhomogeneousPoly=4
	set CInhomogeneousPoly=512
	set GammaRbf=0.0078125
	set CRbf=8388608
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster1v4, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=32
	set CHomogeneousPoly=8
	set GammaInhomogeneousPoly=0.5
	set CInhomogeneousPoly=16
	set GammaRbf=0.125
	set CRbf=64
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster1v5, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=16384
	set CHomogeneousPoly=128
	set GammaInhomogeneousPoly=0.5
	set CInhomogeneousPoly=256
	set GammaRbf=0.015625
	set CRbf=65536
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster2v3, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=262144
	set CHomogeneousPoly=16384
	set GammaInhomogeneousPoly=10
	set CInhomogeneousPoly=512
	set GammaRbf=0.0078125
	set CRbf=8388608
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster2v4, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=8
	set CHomogeneousPoly=2
	set GammaInhomogeneousPoly=0.25
	set CInhomogeneousPoly=10
	set GammaRbf=0.00390625
	set CRbf=1024
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster2v5, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=4096
	set CHomogeneousPoly=32768
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=32
	set GammaRbf=0.015625
	set CRbf=524288
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster3v4, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=2048
	set CHomogeneousPoly=512
	set GammaInhomogeneousPoly=0.25
	set CInhomogeneousPoly=128
	set GammaRbf=0.03125
	set CRbf=8192
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster3v5, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=2048
	set CHomogeneousPoly=32
	set GammaInhomogeneousPoly=0.25
	set CInhomogeneousPoly=256
	set GammaRbf=0.0078125
	set CRbf=32768
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms cluster4v5, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!
	
goto:eof

:safety

	set CLinear=16
	set CHomogeneousPoly=512
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.00390625
	set CRbf=16777216
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe0, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=128
	set CHomogeneousPoly=4096
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.00390625
	set CRbf=33554432
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe01, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=4096
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.0009765625
	set CRbf=33554432
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe012, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=32768
	set GammaInhomogeneousPoly=20
	set CInhomogeneousPoly=4
	set GammaRbf=0.00390625
	set CRbf=33554432
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe0123, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=512
	set GammaInhomogeneousPoly=45
	set CInhomogeneousPoly=8
	set GammaRbf=0.00390625
	set CRbf=33554432
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe01234, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=64
	set CHomogeneousPoly=2048
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.0078125
	set CRbf=4194304
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe1, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=2048
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.0009765625
	set CRbf=33554432
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe2, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=131072
	set CHomogeneousPoly=256
	set GammaInhomogeneousPoly=2
	set CInhomogeneousPoly=8
	set GammaRbf=0.00390625
	set CRbf=8388608
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe3, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=64
	set CHomogeneousPoly=4096
	set GammaInhomogeneousPoly=10
	set CInhomogeneousPoly=32
	set GammaRbf=0.001953125
	set CRbf=16777216
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe4, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=128
	set CHomogeneousPoly=4096
	set GammaInhomogeneousPoly=1
	set CInhomogeneousPoly=2048
	set GammaRbf=0.00390625
	set CRbf=8388608
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe5, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

	set CLinear=128
	set CHomogeneousPoly=2048
	set GammaInhomogeneousPoly=8
	set CInhomogeneousPoly=8
	set GammaRbf=0.00390625
	set CRbf=16777216
	set WeightOne=1
	set WeightMinusOne=1
	call:train_svms qolunsafe6, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!

goto:eof


REM Creates model file directories for all kernel types
REM Function takes one parameter: BaseDir
:create_directories

	set BaseDir=%~1
	echo. & echo. & echo Using BaseDir: %BaseDir% & echo. & echo.

	set LinearKernelModelsDir=%BaseDir%linear\
	set HomogeneousPolyKernelModelsDir=%BaseDir%homogeneous_poly\
	set InhomogeneousPolyKernelModelsDir=%BaseDir%inhomogeneous_poly\
	set RbfKernelModelsDir=%BaseDir%rbf\

	REM Create directories
	if not exist %LinearKernelModelsDir% (
		echo Creating directory %LinearKernelModelsDir%
		mkdir %LinearKernelModelsDir%
	)

	if not exist %HomogeneousPolyKernelModelsDir% (
		echo Creating directory %HomogeneousPolyKernelModelsDir%
		mkdir %HomogeneousPolyKernelModelsDir%
	)

	if not exist %InhomogeneousPolyKernelModelsDir% (
		echo Creating directory %InhomogeneousPolyKernelModelsDir%
		mkdir %InhomogeneousPolyKernelModelsDir%
	)

	if not exist %RbfKernelModelsDir% (
		echo Creating directory %RbfKernelModelsDir%
		mkdir %RbfKernelModelsDir%
	)

goto:eof

REM Train SVMs for all kernel types
:train_svms
	
	set TrainingFile=%~1.train
	set ModelFile=%~1.model
	set Block=%~2
	set CLinear=%~3
	set CHomogeneousPoly=%~4
	set GammaInhomogeneousPoly=%~5
	set CInhomogeneousPoly=%~6
	set GammaRbf=%~7
	set CRbf=%~8
	set WeightOne=%~9
	REM silly hack to shift the parameter list in order to access the 10-th one...
	shift
	set WeightMinusOne=%~9
	
	echo. & echo. & echo File name: %TrainingFile% & echo. & echo.

	REM Train SVMs using linear kernel
	echo. & echo. & echo Training linear kernel & echo. & echo.
	svm-train -t 0 -g 1 -c %CLinear% -w1 %WeightOne% -w-1 %WeightMinusOne% %TrainingBaseDir%%Block%\%TrainingFile% %ModelsBaseDir%%Block%\linear\%ModelFile%

	REM Train SVMs using quadratic homogeneous polynomial kernel
	echo. & echo. & echo Training homogeneous polynomial kernel & echo. & echo.
	svm-train -t 1 -d 2 -g 1 -c %CHomogeneousPoly% -w1 %WeightOne% -w-1 %WeightMinusOne% %TrainingBaseDir%%Block%\%TrainingFile% %ModelsBaseDir%%Block%\homogeneous_poly\%ModelFile%

	REM Train SVMs using quadratic inhomogeneous polynomial kernel
	echo. & echo. & echo Training inhomogeneous polynomial kernel & echo. & echo.
	svm-train -t 1 -d 2 -r 1 -g %GammaInhomogeneousPoly% -c %CInhomogeneousPoly% -w1 %WeightOne% -w-1 %WeightMinusOne% %TrainingBaseDir%%Block%\%TrainingFile% %ModelsBaseDir%%Block%\inhomogeneous_poly\%ModelFile%

	REM Train SVMs using inverse quadratic RBF kernel
	echo. & echo. & echo Training rbf kernel & echo. & echo.
	svm-train -t 2 -g %GammaRbf% -c %CRbf% -w1 %WeightOne% -w-1 %WeightMinusOne% %TrainingBaseDir%%Block%\%TrainingFile% %ModelsBaseDir%%Block%\rbf\%ModelFile%

goto:eof