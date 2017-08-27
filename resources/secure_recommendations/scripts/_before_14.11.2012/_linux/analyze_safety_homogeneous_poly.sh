#!/bin/bash

#Function takes 6 parameters: PATH (to file), FILE (name.extension), GAMMA, C (regularization), WEIGHT_ONE (w1), WEIGHT_MINUS_ONE (w-1)
main () {
	local PATH=$1
	#echo; echo; echo Using PATH: $PATH; echo; echo

	local FILE=$2
	#echo; echo; echo Using FILE: $FILE; echo; echo

	local GAMMA=$3
	#echo; echo; echo Using GAMMA: $GAMMA; echo; echo

	local C=$4
	#echo; echo; echo Using C: $C; echo; echo

	local WEIGHT_ONE=$5
	#echo; echo; echo Using w1: $WEIGHT_ONE; echo; echo

	local WEIGHT_MINUS_ONE=$6
	#echo; echo; echo Using w-1: $WEIGHT_MINUS_ONE; echo; echo

	./svm-train -q -v $CROSS_VALIDATION_FOLD -t 1 -d 2 -g $GAMMA -c $C -w1 $WEIGHT_ONE -w-1 $WEIGHT_MINUS_ONE $PATH$FILE
	echo \|$FILE\|$GAMMA\|$C
}

#Reirect output to file
OUTPUT_FILE=safety_homogeneous_poly.out
exec > /tudelft.net/staff-bulk/ewi/mm/ISPLab/mtodor/training_test/results/$OUTPUT_FILE

#Set folders
TRAINING_FILES_DIR=/tudelft.net/staff-bulk/ewi/mm/ISPLab/mtodor/training_test/data/training/safety/

#Set parameters
CROSS_VALIDATION_FOLD=10

echo; echo; echo $(date) Starting safety SVMs analysis; echo
echo Output format: 'Accuracy|Precision|Recall|F-score|BAC|AUC|filename|Gamma|C'; echo; echo
#Call the main function for each file and combination of parameters
for file in $TRAINING_FILES_DIR*.train
do
	#default weights
	WEIGHT_ONE=1
	WEIGHT_MINUS_ONE=1
	
	if [ "`basename ${file%.*}`" == "qolunsafe0" ]; then
		WEIGHT_ONE=0.39
		WEIGHT_MINUS_ONE=1.61
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe1" ]; then
		WEIGHT_ONE=0.57
		WEIGHT_MINUS_ONE=1.43
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe2" ]; then
		WEIGHT_ONE=0.12
		WEIGHT_MINUS_ONE=1.88
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe3" ]; then
		WEIGHT_ONE=0.11
		WEIGHT_MINUS_ONE=1.89
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe4" ]; then
		WEIGHT_ONE=0.10
		WEIGHT_MINUS_ONE=1.90
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe5" ]; then
		WEIGHT_ONE=0.26
		WEIGHT_MINUS_ONE=1.74
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe6" ]; then
		WEIGHT_ONE=0.44
		WEIGHT_MINUS_ONE=1.56
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe01" ]; then
		WEIGHT_ONE=0.96
		WEIGHT_MINUS_ONE=1.04
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe012" ]; then
		WEIGHT_ONE=1.08
		WEIGHT_MINUS_ONE=0.92
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe0123" ]; then
		WEIGHT_ONE=1.19
		WEIGHT_MINUS_ONE=0.81
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe01234" ]; then
		WEIGHT_ONE=1.30
		WEIGHT_MINUS_ONE=0.70
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe06" ]; then
		WEIGHT_ONE=0.83
		WEIGHT_MINUS_ONE=1.17
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe016" ]; then
		WEIGHT_ONE=1.41
		WEIGHT_MINUS_ONE=0.59
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe0126" ]; then
		WEIGHT_ONE=1.53
		WEIGHT_MINUS_ONE=0.47
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe01236" ]; then
		WEIGHT_ONE=1.63
		WEIGHT_MINUS_ONE=0.37
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe056" ]; then
		WEIGHT_ONE=1.09
		WEIGHT_MINUS_ONE=0.91
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe0456" ]; then
		WEIGHT_ONE=1.20
		WEIGHT_MINUS_ONE=0.80
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe03456" ]; then
		WEIGHT_ONE=1.31
		WEIGHT_MINUS_ONE=0.69
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe0246" ]; then
		WEIGHT_ONE=1.06
		WEIGHT_MINUS_ONE=0.94
	fi
	if [ "`basename ${file%.*}`" == "qolunsafe135" ]; then
		WEIGHT_ONE=0.94
		WEIGHT_MINUS_ONE=1.06
	fi
	
	for gamma in 8 2 0.5 0.125 0.03125 0.0078125 0.001953125 0.00048828125 0.0001220703125 0.000030517578125
	do
		for C in 0.03125 0.125 0.5 2 8 32 128 512 2048 8192 32768
		do
			main ${file%/*}/ ${file##*/} $gamma $C $WEIGHT_ONE $WEIGHT_MINUS_ONE
		done
	done
done
echo; echo; echo $(date) Finished safety SVMs analysis; echo; echo

exit 0
