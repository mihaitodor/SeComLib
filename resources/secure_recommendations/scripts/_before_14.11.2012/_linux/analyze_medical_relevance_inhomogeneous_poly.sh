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
	
	./svm-train -q -v $CROSS_VALIDATION_FOLD -t 1 -d 2 -r 1 -g $GAMMA -c $C -w1 $WEIGHT_ONE -w-1 $WEIGHT_MINUS_ONE $PATH$FILE
	echo \|$FILE\|$GAMMA\|$C
}

#Reirect output to file
OUTPUT_FILE=medical_relevance_inhomogeneous_poly.out
exec > /tudelft.net/staff-bulk/ewi/mm/ISPLab/mtodor/training_test/results/$OUTPUT_FILE

#Set folders
TRAINING_FILES_DIR=/tudelft.net/staff-bulk/ewi/mm/ISPLab/mtodor/training_test/data/training/medical_relevance/

#Set parameters
CROSS_VALIDATION_FOLD=10

echo; echo; echo $(date) Starting medical relevance SVMs analysis; echo
echo Output format: 'Accuracy|Precision|Recall|F-score|BAC|AUC|filename|Gamma|C'; echo; echo
#Call the main function for each file and combination of parameters
for file in $TRAINING_FILES_DIR*.train
do
	#default weights
	WEIGHT_ONE=1
	WEIGHT_MINUS_ONE=1
	
	for gamma in 8 2 0.5 0.125 0.03125 0.0078125 0.001953125 0.00048828125 0.0001220703125 0.000030517578125
	do
		for C in 0.03125 0.125 0.5 2 8 32 128 512 2048 8192 32768
		do
			main ${file%/*}/ ${file##*/} $gamma $C $WEIGHT_ONE $WEIGHT_MINUS_ONE
		done
	done
done
echo; echo; echo $(date) Finished medical relevance SVMs analysis; echo; echo

exit 0
