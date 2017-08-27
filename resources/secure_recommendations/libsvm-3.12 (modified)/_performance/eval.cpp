#include <iostream>
#include <vector>
#include <algorithm>
#include <errno.h>
#include <cstring>
#include "svm.h"
#include "eval.h"

#define Malloc(type,n) (type *)malloc((n)*sizeof(type))

typedef std::vector<double> dvec_t;
typedef std::vector<int>    ivec_t;

// prototypes of evaluation functions
double precision(const dvec_t& dec_values, const ivec_t& ty);
double recall(const dvec_t& dec_values, const ivec_t& ty);
double fscore(const dvec_t& dec_values, const ivec_t& ty);
double bac(const dvec_t& dec_values, const ivec_t& ty);
double auc(const dvec_t& dec_values, const ivec_t& ty);
double accuracy(const dvec_t& dec_values, const ivec_t& ty);

// evaluation function pointer
// You can assign this pointer to any above prototype
double (*validation_function)(const dvec_t&, const ivec_t&) = auc;


static char *line = NULL;
static int max_line_len;


static char* readline(FILE *input)
{
	int len;
	
	if(fgets(line,max_line_len,input) == NULL)
		return NULL;

	while(strrchr(line,'\n') == NULL)
	{
		max_line_len *= 2;
		line = (char *) realloc(line,max_line_len);
		len = (int) strlen(line);
		if(fgets(line+len,max_line_len-len,input) == NULL)
			break;
	}
	return line;
}



double precision(const dvec_t& dec_values, const ivec_t& ty){
	size_t size = dec_values.size();
	size_t i;
	int    tp, fp;
	double precision;

	tp = fp = 0;

	for(i = 0; i < size; ++i) if(dec_values[i] >= 0){
		if(ty[i] == 1) ++tp;
		else           ++fp;
	}

	if(tp + fp == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No positive predict label.\n");
		/* /-Michael */
		precision = 0;
	}else
		precision = tp / (double) (tp + fp);

	/* -Michael */
	//printf("Precision = %g%% (%d/%d)\n", 100.0 * precision, tp, tp + fp);
	/* /-Michael */

	return precision;
}



double recall(const dvec_t& dec_values, const ivec_t& ty){
	size_t size = dec_values.size();
	size_t i;
	int    tp, fn; // true_positive and false_negative
	double recall;

	tp = fn = 0;

	for(i = 0; i < size; ++i) if(ty[i] == 1){ // true label is 1
		if(dec_values[i] >= 0) ++tp; // predict label is 1
		else                   ++fn; // predict label is -1
	}

	if(tp + fn == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No postive true label.\n");
		/* /-Michael */
		recall = 0;
	}else
		recall = tp / (double) (tp + fn);
	// print result in case of invocation in prediction

	/* -Michael */
	//printf("Recall = %g%% (%d/%d)\n", 100.0 * recall, tp, tp + fn);
	/* /-Michael */
	
	return recall; // return the evaluation value
}



double fscore(const dvec_t& dec_values, const ivec_t& ty){
	size_t size = dec_values.size();
	size_t i;
	int    tp, fp, fn;
	double precision, recall;
	double fscore;

	tp = fp = fn = 0;

	for(i = 0; i < size; ++i) 
		if(dec_values[i] >= 0 && ty[i] == 1) ++tp;
		else if(dec_values[i] >= 0 && ty[i] == -1) ++fp;
		else if(dec_values[i] <  0 && ty[i] == 1) ++fn;

	if(tp + fp == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No postive predict label.\n");
		/* /-Michael */
		precision = 0;
	}else
		precision = tp / (double) (tp + fp);
	if(tp + fn == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No postive true label.\n");
		/* /-Michael */
		recall = 0;
	}else
		recall = tp / (double) (tp + fn);

	
	if(precision + recall == 0){
		/* -Michael */
		//fprintf(stderr, "warning: precision + recall = 0.\n");
		/* /-Michael */
		fscore = 0;
	}else
		fscore = 2 * precision * recall / (precision + recall);

	/* -Michael */
	//printf("F-score = %g\n", fscore);
	/* /-Michael */
	
	return fscore;
}



double bac(const dvec_t& dec_values, const ivec_t& ty){
	size_t size = dec_values.size();
	size_t i;
	int    tp, fp, fn, tn;
	double specificity, recall;
	double bac;

	tp = fp = fn = tn = 0;

	for(i = 0; i < size; ++i) 
		if(dec_values[i] >= 0 && ty[i] == 1) ++tp;
		else if(dec_values[i] >= 0 && ty[i] == -1) ++fp;
		else if(dec_values[i] <  0 && ty[i] == 1)  ++fn;
		else ++tn;

	if(tn + fp == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No negative true label.\n");
		/* /-Michael */
		specificity = 0;
	}else
		specificity = tn / (double)(tn + fp);
	if(tp + fn == 0){
		/* -Michael */
		//fprintf(stderr, "warning: No positive true label.\n");
		/* /-Michael */
		recall = 0;
	}else
		recall = tp / (double)(tp + fn);

	bac = (specificity + recall) / 2;
	
	/* -Michael */
	//printf("BAC = %g\n", bac);
	/* /-Michael */
	
	return bac;
}



// only for auc
class Comp{
	const double *dec_val;
	public:
	Comp(const double *ptr): dec_val(ptr){}

	/* -Michael: need size_t here!!! */
	//bool operator()(int i, int j) const{
	/* /-Michael */
	/* +Michael */
	bool operator()(size_t i, size_t j) const{
	/* /+Michael */
		return dec_val[i] > dec_val[j];
	}
};


double auc(const dvec_t& dec_values, const ivec_t& ty){
	double roc  = 0;
	size_t size = dec_values.size();
	size_t i;
	std::vector<size_t> indices(size);

	for(i = 0; i < size; ++i) indices[i] = i;

	std::sort(indices.begin(), indices.end(), Comp(&dec_values[0]));

	int tp = 0,fp = 0;
	for(i = 0; i < size; i++) {
		if(ty[indices[i]] == 1) tp++;
		else if(ty[indices[i]] == -1) {
			roc += tp;
			fp++;
		}
	}

	if(tp == 0 || fp == 0)
	{
		/* -Michael */
		//fprintf(stderr, "warning: Too few postive true labels or negative true labels\n");
		/* /-Michael */
		roc = 0;
	}
	else
		roc = roc / tp / fp;

	/* -Michael */
	//printf("AUC = %g\n", roc);
	/* /-Michael */

	return roc;
}



double accuracy(const dvec_t& dec_values, const ivec_t& ty){
	int    correct = 0;
	int    total   = (int) ty.size();
	size_t i;

	for(i = 0; i < ty.size(); ++i)
		if(ty[i] == (dec_values[i] >= 0? 1: -1)) ++correct;

	/* -Michael */
	//printf("Accuracy = %g%% (%d/%d)\n",
	//	(double)correct/total*100,correct,total);
	/* /-Michael */

	return (double) correct / total;
}

/* +Michael */
//computes the average number of support vectors generated during cross validation
double avgSVs(const ivec_t& nSVs){
	double output = 0.0;
	size_t i;

	for (i = 0; i < nSVs.size(); ++i)
		output += nSVs[i];

	return output / nSVs.size();
}
/* /+Michael */



double binary_class_cross_validation(const svm_problem *prob, const svm_parameter *param, int nr_fold)
{
	int i;
	int *fold_start = Malloc(int,nr_fold+1);
	int l = prob->l;
	int *perm = Malloc(int,l);
	int *labels;
	dvec_t dec_values;
	ivec_t ty;

	for(i=0;i<l;i++) perm[i]=i;
	for(i=0;i<l;i++)
	{
		int j = i+rand()%(l-i);
		std::swap(perm[i],perm[j]);
	}
	for(i=0;i<=nr_fold;i++)
		fold_start[i]=i*l/nr_fold;

	for(i=0;i<nr_fold;i++)
	{
		int                begin   = fold_start[i];
		int                end     = fold_start[i+1];
		int                j,k;
		struct svm_problem subprob;

		subprob.l = l-(end-begin);
		subprob.x = Malloc(struct svm_node*,subprob.l);
		subprob.y = Malloc(double,subprob.l);

		k=0;
		for(j=0;j<begin;j++)
		{
			subprob.x[k] = prob->x[perm[j]];
			subprob.y[k] = prob->y[perm[j]];
			++k;
		}
		for(j=end;j<l;j++)
		{
			subprob.x[k] = prob->x[perm[j]];
			subprob.y[k] = prob->y[perm[j]];
			++k;
		}
		struct svm_model *submodel = svm_train(&subprob,param);
		int svm_type = svm_get_svm_type(submodel);
	
		if(svm_type == NU_SVR || svm_type == EPSILON_SVR){
			fprintf(stderr, "wrong svm type");
			exit(1);
		}

		labels = Malloc(int, svm_get_nr_class(submodel));
		svm_get_labels(submodel, labels);

		if(svm_get_nr_class(submodel) > 2) 
		{
			fprintf(stderr,"Error: the number of class is not equal to 2\n");
			exit(-1);
		}

		dec_values.resize(end);
		ty.resize(end);

		for(j=begin;j<end;j++) {
			svm_predict_values(submodel,prob->x[perm[j]], &dec_values[j]);
			ty[j] = (prob->y[perm[j]] > 0)? 1: -1;
		}


		if(labels[0] <= 0) {
			for(j=begin;j<end;j++)
				dec_values[j] *= -1;
		}
	
		svm_free_and_destroy_model(&submodel);
		free(subprob.x);
		free(subprob.y);
		free(labels);
	}		

	free(perm);
	free(fold_start);

	return validation_function(dec_values, ty);	
}

/* +Michael: copied from svm.cpp (libsvm-3.12); required in print_all_binary_class_cross_validation */
// label: label name, start: begin of each class, count: #data of classes, perm: indices to the original data
// perm, length l, must be allocated before calling this subroutine
static void svm_group_classes(const svm_problem *prob, int *nr_class_ret, int **label_ret, int **start_ret, int **count_ret, int *perm)
{
	int l = prob->l;
	int max_nr_class = 16;
	int nr_class = 0;
	int *label = Malloc(int,max_nr_class);
	int *count = Malloc(int,max_nr_class);
	int *data_label = Malloc(int,l);	
	int i;

	for(i=0;i<l;i++)
	{
		int this_label = (int)prob->y[i];
		int j;
		for(j=0;j<nr_class;j++)
		{
			if(this_label == label[j])
			{
				++count[j];
				break;
			}
		}
		data_label[i] = j;
		if(j == nr_class)
		{
			if(nr_class == max_nr_class)
			{
				max_nr_class *= 2;
				label = (int *)realloc(label,max_nr_class*sizeof(int));
				count = (int *)realloc(count,max_nr_class*sizeof(int));
			}
			label[nr_class] = this_label;
			count[nr_class] = 1;
			++nr_class;
		}
	}

	int *start = Malloc(int,nr_class);
	start[0] = 0;
	for(i=1;i<nr_class;i++)
		start[i] = start[i-1]+count[i-1];
	for(i=0;i<l;i++)
	{
		perm[start[data_label[i]]] = i;
		++start[data_label[i]];
	}
	start[0] = 0;
	for(i=1;i<nr_class;i++)
		start[i] = start[i-1]+count[i-1];

	*nr_class_ret = nr_class;
	*label_ret = label;
	*start_ret = start;
	*count_ret = count;
	free(data_label);
}
/* /+Michael */

/* +Michael: prints accuacy|precision|recall|fscore|bac|auc */
void print_all_binary_class_cross_validation(const svm_problem *prob, const svm_parameter *param, int nr_fold)
{
	/* Copied from binary_class_cross_validation */
	int i;
	int *fold_start = Malloc(int,nr_fold+1);
	int l = prob->l;
	int *perm = Malloc(int,l);
	int *labels;
	dvec_t dec_values;
	ivec_t ty;

	/* +Michael: store the number of support vectors during cross validation */
	ivec_t nSVs;
	/* /+Michael */

	/* -Michael: it seems that the latest version of libsvm implements this in a different way (see void svm_cross_validation in svm.cpp) */
	/*
	for(i=0;i<l;i++) perm[i]=i;
	for(i=0;i<l;i++)
	{
		int j = i+rand()%(l-i);
		std::swap(perm[i],perm[j]);
	}
	for(i=0;i<=nr_fold;i++)
		fold_start[i]=i*l/nr_fold;
	*/
	/* /-Michael */

	/* +Michael: copied from svm_cross_validation */
	int nr_class;

	// stratified cv may not give leave-one-out rate
	// Each class to l folds -> some folds may have zero elements
	if((param->svm_type == C_SVC ||
	    param->svm_type == NU_SVC) && nr_fold < l)
	{
		int *start = NULL;
		int *label = NULL;
		int *count = NULL;
		svm_group_classes(prob,&nr_class,&label,&start,&count,perm);

		// random shuffle and then data grouped by fold using the array perm
		int *fold_count = Malloc(int,nr_fold);
		int c;
		int *index = Malloc(int,l);
		for(i=0;i<l;i++)
			index[i]=perm[i];
		for (c=0; c<nr_class; c++) 
			for(i=0;i<count[c];i++)
			{
				int j = i+rand()%(count[c]-i);
				std::swap(index[start[c]+j],index[start[c]+i]);
			}
		for(i=0;i<nr_fold;i++)
		{
			fold_count[i] = 0;
			for (c=0; c<nr_class;c++)
				fold_count[i]+=(i+1)*count[c]/nr_fold-i*count[c]/nr_fold;
		}
		fold_start[0]=0;
		for (i=1;i<=nr_fold;i++)
			fold_start[i] = fold_start[i-1]+fold_count[i-1];
		for (c=0; c<nr_class;c++)
			for(i=0;i<nr_fold;i++)
			{
				int begin = start[c]+i*count[c]/nr_fold;
				int end = start[c]+(i+1)*count[c]/nr_fold;
				for(int j=begin;j<end;j++)
				{
					perm[fold_start[i]] = index[j];
					fold_start[i]++;
				}
			}
		fold_start[0]=0;
		for (i=1;i<=nr_fold;i++)
			fold_start[i] = fold_start[i-1]+fold_count[i-1];
		free(start);	
		free(label);
		free(count);	
		free(index);
		free(fold_count);
	}
	else
	{
		for(i=0;i<l;i++) perm[i]=i;
		for(i=0;i<l;i++)
		{
			int j = i+rand()%(l-i);
			std::swap(perm[i],perm[j]);
		}
		for(i=0;i<=nr_fold;i++)
			fold_start[i]=i*l/nr_fold;
	}
	/* /+Michael */

	for(i=0;i<nr_fold;i++)
	{
		int                begin   = fold_start[i];
		int                end     = fold_start[i+1];
		int                j,k;
		struct svm_problem subprob;

		subprob.l = l-(end-begin);
		subprob.x = Malloc(struct svm_node*,subprob.l);
		subprob.y = Malloc(double,subprob.l);

		k=0;
		for(j=0;j<begin;j++)
		{
			subprob.x[k] = prob->x[perm[j]];
			subprob.y[k] = prob->y[perm[j]];
			++k;
		}
		for(j=end;j<l;j++)
		{
			subprob.x[k] = prob->x[perm[j]];
			subprob.y[k] = prob->y[perm[j]];
			++k;
		}
		struct svm_model *submodel = svm_train(&subprob,param);
		int svm_type = svm_get_svm_type(submodel);
	
		if(svm_type == NU_SVR || svm_type == EPSILON_SVR){
			fprintf(stderr, "wrong svm type");
			exit(1);
		}

		labels = Malloc(int, svm_get_nr_class(submodel));
		svm_get_labels(submodel, labels);

		if(svm_get_nr_class(submodel) > 2) 
		{
			fprintf(stderr,"Error: the number of class is not equal to 2\n");
			exit(-1);
		}

		dec_values.resize(end);
		ty.resize(end);

		for(j=begin;j<end;j++) {
			svm_predict_values(submodel,prob->x[perm[j]], &dec_values[j]);
			ty[j] = (prob->y[perm[j]] > 0)? 1: -1;
		}


		if(labels[0] <= 0) {
			for(j=begin;j<end;j++)
				dec_values[j] *= -1;
		}

		/* +Michael: store the number of generated support vectors */
		nSVs.push_back(submodel->l);
		/* /+Michael */
	
		svm_free_and_destroy_model(&submodel);
		free(subprob.x);
		free(subprob.y);
		free(labels);
	}		

	free(perm);
	free(fold_start);
	/* /Copied from... */

	/* +Michael: compute true / false positives and true / false negatives and te number of SVs generated by training the model on the entire training data */
	int truePositives = 0, falsePositives = 0, trueNegatives = 0, falseNegatives = 0, trainingNumSVs = 0;

	for(size_t i = 0; i < dec_values.size(); ++i) 
		if(dec_values[i] >= 0 && ty[i] == 1) ++truePositives;
		else if(dec_values[i] >= 0 && ty[i] == -1) ++falsePositives;
		else if(dec_values[i] <  0 && ty[i] == 1)  ++falseNegatives;
		else ++trueNegatives;

	//compute and print the total number of SVs, if trained with the current parameters
	struct svm_model *model = svm_train(prob, param);
	trainingNumSVs = model->l;
	svm_free_and_destroy_model(&model);
	/* /+Michael */

	/* print accuracy|precision|recall|fscore|bac|auc */
	double accuracyValue = accuracy(dec_values, ty);
	double precisionValue = precision(dec_values, ty);
	double recallValue = recall(dec_values, ty);
	double fscoreValue = fscore(dec_values, ty);
	double bacValue = bac(dec_values, ty);
	double aucValue = auc(dec_values, ty);
	double avgNumSVs = avgSVs(nSVs);

	printf("%f|%f|%f|%f|%f|%f|%d|%d|%.1f|%d", accuracyValue * 100, precisionValue, recallValue, fscoreValue, bacValue, aucValue, falsePositives, falseNegatives, avgNumSVs, trainingNumSVs);
}

/* /+Michael */

void binary_class_predict(FILE *input, FILE *output){
	int    total = 0;
	int    *labels;
	int    max_nr_attr = 64;
	struct svm_node *x = Malloc(struct svm_node, max_nr_attr);
	dvec_t dec_values;
	ivec_t true_labels;


	int svm_type=svm_get_svm_type(model);
	
	if (svm_type==NU_SVR || svm_type==EPSILON_SVR){
		fprintf(stderr, "wrong svm type.");
		exit(1);
	}

	labels = Malloc(int, svm_get_nr_class(model));
	svm_get_labels(model, labels);
	
	max_line_len = 1024;
	line = (char *)malloc(max_line_len*sizeof(char));
	while(readline(input) != NULL)
	{
		int i = 0;
		double target_label, predict_label;
		char *idx, *val, *label, *endptr;
		int inst_max_index = -1; // strtol gives 0 if wrong format, and precomputed kernel has <index> start from 0

		label = strtok(line," \t");
		target_label = strtod(label,&endptr);
		if(endptr == label)
			exit_input_error(total+1);

		while(1)
		{
			if(i>=max_nr_attr - 2)	// need one more for index = -1
			{
				max_nr_attr *= 2;
				x = (struct svm_node *) realloc(x,max_nr_attr*sizeof(struct svm_node));
			}

			idx = strtok(NULL,":");
			val = strtok(NULL," \t");

			if(val == NULL)
				break;
			errno = 0;
			x[i].index = (int) strtol(idx,&endptr,10);
			if(endptr == idx || errno != 0 || *endptr != '\0' || x[i].index <= inst_max_index)
				exit_input_error(total+1);
			else
				inst_max_index = x[i].index;

			errno = 0;
			x[i].value = strtod(val,&endptr);
			if(endptr == val || errno != 0 || (*endptr != '\0' && !isspace(*endptr)))
				exit_input_error(total+1);

			++i;
		}
		x[i].index = -1;

		predict_label = svm_predict(model,x);
		fprintf(output,"%g\n",predict_label);


		double dec_value;
		svm_predict_values(model, x, &dec_value);
		true_labels.push_back((target_label > 0)? 1: -1);
		if(labels[0] <= 0) dec_value *= -1;
		dec_values.push_back(dec_value);
	}	

	validation_function(dec_values, true_labels);

	free(labels);
	free(x);
}
