@echo off

set ModelsDir=D:\mtodor\_Work\Projects\KinderedSpirits\_output\x64\MPIRDebug\models\medical_relevance
REM set ModelsDir=D:\mtodor\_Work\Projects\KinderedSpirits\_output\x64\MPIRDebug\models\safety

set InputFile=D:\mtodor\_Work\Projects\KinderedSpirits\_output\x64\MPIRDebug\input\philips.test
set OutputFile=D:\mtodor\_Work\Projects\KinderedSpirits\_output\x64\MPIRDebug\predict.out

set LinearKernelModelFiles=%ModelsDir%\linear\*.model
set HomogeneousPolyKernelModelFiles=%ModelsDir%\homogeneous_poly\*.model
set InhomogeneousPolyKernelModelFiles=%ModelsDir%\inhomogeneous_poly\*.model
set RbfKernelModelFiles=%ModelsDir%\rbf\*.model

echo. & echo. & echo Predict linear kernel
for  %%i in (%LinearKernelModelFiles%) do (
	svm-predict %InputFile% %%i %OutputFile%
)

echo. & echo. & echo Predict homogeneous polynomial kernel
for %%i in (%HomogeneousPolyKernelModelFiles%) do (
	svm-predict %InputFile% %%i %OutputFile%
)

echo. & echo. & echo Predict inhomogeneous polynomial kernel
for %%i in (%InhomogeneousPolyKernelModelFiles%) do (
	svm-predict %InputFile% %%i %OutputFile%
)

echo. & echo. & echo Predict rbf kernel
for %%i in (%RbfKernelModelFiles%) do (
	svm-predict %InputFile% %%i %OutputFile%
)