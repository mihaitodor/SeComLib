/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Mihai Todor (todormihai@gmail.com)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
@file plaintext-recommendations.cpp
@brief Plaintext implementation for "Privacy-Preserving Recommender Systems in eHealth Systems", Arjan Jeckmans, Pieter Hartel, Michael Beye, Zekeriya Erkin, Mihai Todor, Inald Lagendijk, Jeroen Doumen, Tanya Ignatenko, 2013.
@author Mihai Todor (todormihai@gmail.com)
*/
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <exception>
#include <fstream>
#include <sstream>

#include "svm.h"

/* helpers */

//include headers required for directory traversal
#if defined(_WIN32)
	//disable useless stuff before adding windows.h
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
#else
	#include "dirent.h"
#endif
std::vector<std::string> listFilesInDirectory(const std::string &directory)
{
	std::vector<std::string> output;

//create each platform-specific implementation
#if defined(_WIN32)

	//select all files
	std::string tempDirectory = directory + "*";

	//initialize the WIN32_FIND_DATA structure
	WIN32_FIND_DATA directoryHandle = {0};

	//set the directory
	std::wstring wideString = std::wstring(tempDirectory.begin(), tempDirectory.end());
	LPCWSTR directoryPath = wideString.c_str();

	//iterate over all files
	HANDLE handle = FindFirstFile(directoryPath, &directoryHandle);
	while(INVALID_HANDLE_VALUE != handle)
	{
		//skip non-files
		if (!(directoryHandle.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			//convert from WCHAR to std::string
			size_t size = wcslen(directoryHandle.cFileName);
			std::vector<char> buffer;
			buffer.resize(2 * size + 2);
			size_t convertedCharacters = 0;
			wcstombs_s(&convertedCharacters, buffer.data(), 2 * size + 2, directoryHandle.cFileName, _TRUNCATE);
			//trim the null characters (ASCII characters won't fill the vector, since they require fewer bytes)
			//convertedCharacters includes the null character, which we want to discard
			std::string file(buffer.begin(), buffer.begin() + convertedCharacters - 1);

			//add the absolute file path
			output.emplace_back(file);
		}
			
		if(false == FindNextFile(handle, &directoryHandle)) break;
	}

	//close the handle
	FindClose(handle);

#else

	DIR *directoryHandle = opendir(directory.c_str());
	if (NULL != directoryHandle)
	{
		/*
		//determine the absolute path of the directory
		char absoluteDirectoryPathBuffer[PATH_MAX + 1];
		realpath(directory.c_str(), absoluteDirectoryPathBuffer);
		std::string absoluteDirectoryPath(absoluteDirectoryPathBuffer);
		absoluteDirectoryPathBuffer += "/";//add separator
		*/
		dirent *entry = readdir(directoryHandle);
		while (NULL != entry)
		{
			//skip directories and select only files (hopefully)
			//if ((DT_DIR != entry->d_type) && (DT_UNKNOWN == entry->d_type))
			if (DT_REG == entry->d_type)
			{
				output.emplace_back(entry->d_name);
			}

			//go to next entry
			entry = readdir(directoryHandle);
		}
		closedir(directoryHandle);
	}

#endif

	return output;
}

/* /helpers */

class Svm
{
public:
	Svm (const std::string &directory, const std::string &modelFile);

	~Svm ();

	bool ContainsLabel (unsigned short label);

	std::string GetUnsafeClasses ();

	std::string GetModelFileName ();

	struct svm_model *model;

private:
	std::string modelFile;

	std::vector<unsigned short> unsafeClasses;
};

class TestData
{
public:
	TestData (const std::string &directory, const std::string &testFile, const unsigned short &attributeCount);
	~TestData () {}

	std::string GetUnsafeClasses ();

	std::vector<std::vector<double>> x;
	std::vector<unsigned short int> clusterLabels;
	std::vector<unsigned short int> qualityOfLifeLabels;

private:
	std::string testFilePath;

	std::vector<unsigned short> unsafeClasses;

	unsigned short attributeCount;
	void loadTestData ();
};

Svm::Svm (const std::string &directory, const std::string &modelFile) : modelFile(modelFile)
{
	//For the safety SVMs:
	//file name format: qolunsafe0123456.model where 0123456 are a series of digits representing the unsafe classes
	//extract each class into the unsafeClasses vector
	if (std::string::npos != modelFile.find("qolunsafe"))
	{
		//iterate over each class (digit) in the file name
		for (size_t i = std::string("qolunsafe").size(); i <  modelFile.find("."); ++i)
		{
			//the difference between any digit and '0' will yield the desired numeric value
			this->unsafeClasses.emplace_back(modelFile[i] - '0');
		}

		std::sort(this->unsafeClasses.begin(), this->unsafeClasses.end());
	}

	this->model = svm_load_model((directory + modelFile).c_str());

	if (NULL == this->model) throw std::runtime_error("Can't load model file!");
}

Svm::~Svm ()
{
	svm_free_and_destroy_model(&this->model);
	//std::cout << "killing svm...";
}

bool Svm::ContainsLabel (unsigned short label)
{
	if (std::find(this->unsafeClasses.begin(), this->unsafeClasses.end(), label) != this->unsafeClasses.end()) return true;

	return false;
}

std::string Svm::GetUnsafeClasses ()
{
	std::stringstream stringStream;
	for (std::vector<unsigned short>::const_iterator i = this->unsafeClasses.begin(); i != this->unsafeClasses.end(); ++i)
	{
		stringStream << *i;
	}
	return stringStream.str();
}

std::string Svm::GetModelFileName ()
{
	return this->modelFile;
}

TestData::TestData (const std::string &directory, const std::string &testFile, const unsigned short &attributeCount): testFilePath(directory + testFile), attributeCount(attributeCount)
{
	//For the safety test data:
	//file name format: philips.test.unsafe0123456 where 0123456 are a series of digits representing the unsafe classes
	//extract each class into the unsafeClasses vector
	if (std::string::npos != testFile.find(".unsafe"))
	{
		//iterate over each class (digit) in the file name
		for (size_t i = testFile.find_last_not_of("0123456789") + 1; i < testFile.size(); ++i)
		{
			//the difference between any digit and '0' will yield the desired numeric value
			this->unsafeClasses.emplace_back(testFile[i] - '0');
		}

		std::sort(this->unsafeClasses.begin(), this->unsafeClasses.end());
	}

	this->loadTestData ();
}

std::string TestData::GetUnsafeClasses ()
{
	std::stringstream stringStream;
	for (std::vector<unsigned short>::const_iterator i = this->unsafeClasses.begin(); i != this->unsafeClasses.end(); ++i)
	{
		stringStream << *i;
	}
	return stringStream.str();
}

void TestData::loadTestData ()
{
	//create a file stream to the imput file
	std::ifstream fileStream(this->testFilePath);

	std::string line;
	//iterate over all the lines in the file and populate the safetyTestData structure column by column
	while (std::getline(fileStream, line))
	{
		//make sure the file exists and it is readable
		if (!fileStream.good())
		{
			/// @todo Throw a custom exception here
			throw std::runtime_error("Can't open the test file.");
		}

		std::string::size_type hashPosition = line.find('#');
		std::string::size_type clPosition = line.find("cl");
		std::string::size_type qolPosition = line.find("qol");
		std::string::size_type genPosition = line.find("gen");
		if (std::string::npos == hashPosition || std::string::npos == clPosition || std::string::npos == qolPosition || std::string::npos == genPosition)
		{
			throw std::runtime_error("Label(s) not found in input file.");
		}
			
		std::string::size_type clQolDelimiter = line.find(' ', clPosition);
		std::string::size_type qolGenDelimiter = line.find(' ', qolPosition);
	
		if (std::string::npos == clQolDelimiter || std::string::npos == qolGenDelimiter)
		{
			throw std::runtime_error("Labels should be delimited by a space character.");
		}
			
		/// Use std::istringstream to manipulate the label data
		std::istringstream clusterLabel(line.substr(clPosition + 3, clQolDelimiter));
		//the input line should end after the qol value
		std::istringstream qualityOfLifeLabel(line.substr(qolPosition + 4, qolGenDelimiter));
		//we're not interested in the gen label

		if (!clusterLabel || !qualityOfLifeLabel)
		{
			throw std::runtime_error("Malformed labels detected in input file.");
		}

		unsigned short labelValue;

		/// Parse label data and persist it in our internal vectors.
			
		//the input test data indexes the clusters starting from 1.
		clusterLabel >> labelValue;
		if (labelValue < 1U || labelValue > 5U)
		{
			throw std::runtime_error("Invalid cluster label.");
		}

		this->clusterLabels.emplace_back(labelValue);

		qualityOfLifeLabel >> labelValue;
		/// If the SVM result is negative, then the label must be contained in the model file name (valid values: 0-6) for correct predictions
		if (labelValue > 6U)
		{
			throw std::runtime_error("Invalid quality of life label.");
		}
		/// If the SVM result is negative, then the label must be contained in the model file name (valid values: 0-6) for corrct predictions
		this->qualityOfLifeLabels.emplace_back(labelValue);

		/// Build a vector of encrypted attributes and add it to the matrix
		std::vector<double> tempX;
			
		/// Extract the attribute values.
		/// Each attribute is stored as index:value, where index >= 1.
		/// We assume that each input line does not omit any attribute value (if it's 0), even though libsvm accepts this, so we simply discard the attribute indexes.
		std::string::size_type attributeValueStartPosition = line.find(':');
		if (std::string::npos == attributeValueStartPosition)
		{
			throw std::runtime_error("Can't find the first attribute.");
		}
		for (unsigned int i = 0; i < this->attributeCount; ++i)
		{
			std::string::size_type attributeDelimiterPosition = line.find(' ', attributeValueStartPosition);
			if (std::string::npos == attributeDelimiterPosition)
			{
				throw std::runtime_error("Input line does not contain the required number of attributes.");
			}
				
			//extract the current attribute value to stringstream so that we can convert it easily to double
			std::istringstream attributeStream(line.substr(attributeValueStartPosition + 1, attributeDelimiterPosition - attributeValueStartPosition - 1));
				
			if (!attributeStream)
			{
				throw std::runtime_error("Invalid attribute value detected.");
			}
				
			//std::cout << attributeStream.str() << std::endl;

			//convert stream to double (are 8 bytes / 15 digits enough???)
			double attribute;
			attributeStream >> attribute;
			tempX.push_back(attribute);
				
			//jump to the next attribute
			attributeValueStartPosition = line.find(':', attributeValueStartPosition + 1);
		}

		//populate the x matrix
		this->x.emplace_back(tempX);
	}

	//close the file stream
	fileStream.close();


#if 0 //old version of the code... (doesn't handle numbers in scientific notation properly!!!)

	/// Match any sequence of numbers in the following format: number:decimal_number.
	/// Consider the decimal separator to be "."
	std::regex attributesPattern("([0-9]+):(-?[0-9|.]+)");

	/// Match the labels located at the end of each line after the # sign
	std::regex labelsPattern("cl:([0-9]+).*qol:([0-9]+)");

	std::string line;
	//iterate over all the lines in the file
	while (std::getline(fileStream, line))
	{
		/// Extract the label from each line, transform them to match our internal conventions and store them for accuracy measurements
		std::smatch label;
			
		if (!std::regex_search(line, label, labelsPattern))
		{
			throw std::runtime_error("Labels not found in input file.");
		}

		/// Use std::istringstream to manipulate the label data
		std::istringstream clusterLabel(label[1]);
		std::istringstream qualityOfLifeLabel(label[2]);

		if (!clusterLabel || !qualityOfLifeLabel)
		{
			throw std::runtime_error("Malformed labels detected in input file.");
		}

		unsigned short labelValue;

		/// Parse label data and persist it in our internal vectors. The input test data indexes the clusters starting from 1.
		clusterLabel >> labelValue;
		if (labelValue < 1U || labelValue > 5U)
		{
			throw std::runtime_error("Invalid cluster label.");
		}

		this->clusterLabels.emplace_back(labelValue);

		qualityOfLifeLabel >> labelValue;
		if (labelValue > 6U)
		{
			throw std::runtime_error("Invalid quality of life label.");
		}
		/// If the SVM result is negative, then the label must be contained in the model file name (valid values: 0-6) for corrct predictions
		this->qualityOfLifeLabels.emplace_back(labelValue);

		/// Build a vector of encrypted attributes and add it to the matrix
		std::vector<double> tempX;

		/// Each attribute is stored as index:value, where index >= 1
		unsigned int previousIndex = 0U;
		unsigned int currentIndex;

		/// Iterate over every occurence of the pattern in the current line
		for (std::sregex_iterator i(line.begin(), line.end(), attributesPattern); i != std::sregex_iterator(); ++i)
		{
			/**
			We assume that each line contains the attribute values, ordered by index value.
			If the value is 0, then the index:value pair is omitted, so we need to add it as an encryption of 0
			*/

			//parse the index and store it in currentIndex
			std::istringstream attributeIndexStream((*i)[1]);
			if (!attributeIndexStream)
			{
				throw std::runtime_error("Invalid attribute index detected.");
			}

			attributeIndexStream >> currentIndex;

			//add 0s to the attribute vector for missing indexes
			for (unsigned int j = 0; j < currentIndex - previousIndex - 1; j++)
			{
				tempX.push_back(0.0);
			}

			//convert the string containing the current attribute value to stringstream so that we can convert it easily to double
			std::istringstream attributeStream((*i)[2]);
			if (!attributeStream)
			{
				throw std::runtime_error("Invalid attribute value detected.");
			}

			//convert stream to double (are 8 bytes / 15 digits enough???)
			double attribute;
			attributeStream >> attribute;

			//apply scaling
			//in case of negative values, remap them at the end of the key space
			tempX.push_back(attribute);

			//advance the attribute index
			previousIndex = currentIndex;
		}

		// if the last attribute(s) is(were) omitted (having the value 0), we need to add them
		if (TestData::attributeCount > tempX.size())
		{
			//add 0s to the end of the attribute vector for missing indexes
			for (unsigned int i = 0; i < tempX.size() - attributeCount; i++)
			{
				tempX.push_back(0.0);
			}
		}

		//populate the x matrix
		this->x.emplace_back(tempX);
	}

#endif
}

#if 0 //useless old stuff... 
bool getLabel (const std::vector<double> &dataRow, const std::shared_ptr<const Svm> &svm)
{
	//quick&dirty: use libsvm to do predictions... :(

	int max_nr_attr = 64;
	int inst_max_index = -1;
	struct svm_node *x = (struct svm_node *) malloc(max_nr_attr*sizeof(struct svm_node));
	for (int i = 0; i < static_cast<int>(dataRow.size()); ++i)
	{
		if(i>=max_nr_attr-1)	// need one more for index = -1
		{
			max_nr_attr *= 2;
			x = (struct svm_node *) realloc(x,max_nr_attr*sizeof(struct svm_node));
		}

		//if(val == NULL)
			//break;
		//errno = 0;

		x[i].index = i + 1;//silly libsvm file format convention (indexing starts from 1)

		//if(endptr == idx || errno != 0 || *endptr != '\0' || x[i].index <= inst_max_index)
		//	exit_input_error(total+1);
		//else
			inst_max_index = x[i].index;

		//errno = 0;
		x[i].value = dataRow[i];
		//if(endptr == val || errno != 0 || (*endptr != '\0' && !isspace(*endptr)))
		//	exit_input_error(total+1);

		//++i;
	}

	x[static_cast<int>(dataRow.size())].index = -1;

 	double predict_label = svm_predict(svm->model, x);

	free(x);
	
	return predict_label > 0 ? true : false;
}
#endif

//both vectors must have the same number of elements
double dot (const std::vector<double> &x, const svm_node *s)
{
	double output = 0;
	//for (std::vector<double>::const_iterator i = x.begin(), j = s.begin(); i != x.end() || j != s.end(); ++i, ++j)
	for (size_t i = 0; i < x.size(); ++i)
	{
		output += x[i] * s->value;
		++s;
	}

	return output;
}

//both vectors must have the same number of elements
double squaredDiff (const std::vector<double> &x, const svm_node *s)
{
	double output = 0;
	//for (std::vector<double>::const_iterator i = x.begin(), j = s.begin(); i != x.end() || j != s.end(); ++i, ++j)
	for (size_t i = 0; i < x.size(); ++i)
	{
		output += (x[i] - s->value) * (x[i] - s->value);
		++s;
	}

	return output;
}

bool getLabel (const std::vector<double> &dataRow, const std::shared_ptr<const Svm> &svm)
{
	double predictionValue = 0;

	//we either have labels (1, 2) or (1, -1). If they are reversed, we need to reverse the sign of the prediction
	int sign = 1;
	if ((std::abs(svm->model->label[0]) > std::abs(svm->model->label[1])) || (svm->model->label[0] == -1 && svm->model->label[1] == 1))
	{
		sign = -1;
	}

	for (int i = 0; i < svm->model->l; ++i)
	{
		/// Extract current support vector
		std::vector<double> supportVector;
		//create an iterator for the svm->model->SV[i] "array"

		//a_i is stored in svm->model->sv_coef[0][i]
		switch(svm->model->param.kernel_type)
		{
			case LINEAR:
				predictionValue += svm->model->sv_coef[0][i] * dot(dataRow, svm->model->SV[i]);
				break;
			case POLY:
				predictionValue += svm->model->sv_coef[0][i] * std::pow(svm->model->param.gamma * dot(dataRow, svm->model->SV[i]) + svm->model->param.coef0, svm->model->param.degree);
				break;
			case RBF:
				//printf("%.10f\n", 1.0 / (1.0 + svm->model->param.gamma * squaredDiff(dataRow, svm->model->SV[i])));
				//printf("%.10f\n", svm->model->sv_coef[0][i] * (1.0 / (1.0 + svm->model->param.gamma * squaredDiff(dataRow, svm->model->SV[i]))));
				predictionValue += svm->model->sv_coef[0][i] * (1.0 / (1.0 + svm->model->param.gamma * squaredDiff(dataRow, svm->model->SV[i])));
				break;
		}
	}

	//add b (which is stored as -(svm->model->rho[0]))
	//printf("%.10f\n", predictionValue);
	//printf("%.10f\n", -svm->model->rho[0]);
	predictionValue -= svm->model->rho[0];

	//std::cout << sign * predictionValue << std::endl;

	return sign * predictionValue > 0 ? true : false;
}


std::vector<unsigned short> getTotalClusterVotes (const std::vector<bool> &votes, const unsigned short &medicalRelevanceClusterCount)
{
	//initialize the cluster votes vector with zeroes
	std::vector<unsigned short> clusterVotes(medicalRelevanceClusterCount, 0U);

	/// We computed only the SVM predictions for cluster(i, j), where i < j, because for i > j, prediction(i, j) = 1 - prediction(j, i)
	unsigned int svmCounter = 0;
	for (unsigned int i = 0; i < medicalRelevanceClusterCount; ++i)
	{
		for (unsigned int j = i + 1; j < medicalRelevanceClusterCount; ++j)
		{
			if (votes[svmCounter])
				++clusterVotes[i];
			else
				++clusterVotes[j];

			//increment SVM counter
			++svmCounter;
		}
	}

	return clusterVotes;
}

//returns 1 - 5 if unique max found; otherwise returns 0
unsigned short evaluateMaximum (const std::vector<unsigned short> &input)
{
	/// Set the maximum as the first value
	unsigned short maximum = input[0];
	//store the index of the maximum value
	unsigned short index = 0;

	//detect if the maximum value occurs more than once in the input data
	bool uniqueMaximumValue = true;

	/// Compare maximum with the other values to determine the real maximum
	for (unsigned short i = 1; i < input.size(); ++i)
	{
		if (maximum == input[i])
		{
			uniqueMaximumValue = false;
		}

		if (maximum < input[i])
		{
			maximum = input[i];
			index = i;
			uniqueMaximumValue = true;//reset this flag if we update the maximum
		}
	}

	return uniqueMaximumValue ? index + 1 : 0;
}

int main ()
{
	//Valid values: linear, homogeneous_poly, inhomogeneous_poly, rbf
	std::string kernel = "rbf";
	
	std::string testDataDirectory = "D:/mtodor/_Work/Projects/KindredSpirits/_output/x64/MPIRDebug/input/";
	std::string medicalRelevanceTestDataFile = "philips.test.medical";
	std::string medicalRelevanceModelsDirectory = "D:/mtodor/_Work/Projects/KindredSpirits/_output/x64/MPIRDebug/models/medical_relevance/" + kernel + "/";
	std::string safetyModelsDirectoy = "D:/mtodor/_Work/Projects/KindredSpirits/_output/x64/MPIRDebug//models/safety/" + kernel + "/";

	unsigned short medicalRelevanceClusterCount = 5;
	unsigned short attributeCount = 10;

	try
	{
		//load the medical relevance SVMs
		std::vector<std::shared_ptr<Svm>> medicalRelevanceSvmVector;
		for (unsigned int i = 0; i < medicalRelevanceClusterCount; ++i)
		{
			for (unsigned int j = i + 1; j < medicalRelevanceClusterCount; ++j)
			{
				std::stringstream fileName;

				//construct the file path
				fileName << "cluster" << (i + 1) << "v" << (j + 1) << ".model";
				
				//std::shared_ptr ensures that the SecureSvm objects will not get passed by value
				medicalRelevanceSvmVector.emplace_back(std::shared_ptr<Svm>(new Svm(medicalRelevanceModelsDirectory, fileName.str())));

				std::cout << "Loaded " << fileName.str() << "; nSV: " << medicalRelevanceSvmVector.back()->model->l << std::endl;
			}
		}
		std::cout << "Finished loading data from " << medicalRelevanceSvmVector.size() << " medical relevance block model files." << std::endl;

		//load the safety SVMs
		std::vector<std::shared_ptr<Svm>> safetySvmVector;
		std::vector<std::string> models = listFilesInDirectory(safetyModelsDirectoy);
		for (std::vector<std::string>::const_iterator modelFileIterator = models.begin(); modelFileIterator != models.end(); ++modelFileIterator)
		{
			safetySvmVector.emplace_back(std::shared_ptr<Svm>(new Svm(safetyModelsDirectoy, (*modelFileIterator))));

			std::cout << "Loaded " << *modelFileIterator << "; nSV: " << safetySvmVector.back()->model->l << std::endl;
		}
		std::cout << "Finished loading data from " << safetySvmVector.size() << " safety block model files." << std::endl;

		//load the test files
		TestData medicalRelevanceTestData(testDataDirectory, medicalRelevanceTestDataFile, attributeCount);

		std::map<std::string, std::shared_ptr<TestData>> safetyBlockTestDataMap;
		std::vector<std::string> testDataFiles = listFilesInDirectory(testDataDirectory);
		//load the safety test files
		for (std::vector<std::string>::const_iterator testDataFile = testDataFiles.begin(); testDataFile != testDataFiles.end(); ++testDataFile)
		{
			if (std::string::npos != (*testDataFile).find("philips.test.unsafe"))
			{
				TestData testData(testDataDirectory, *testDataFile, attributeCount);

				safetyBlockTestDataMap[testData.GetUnsafeClasses()] = std::make_shared<TestData>(testData);
			}
		}
		std::cout << "Finished loading test data." << std::endl;

		//compute medical relevance predictions and accuracy
		std::vector<unsigned short> medicalRelevancePredictions;//possible values: 1 - 5; 0 if multiple maximums
		unsigned int medicalRelevanceBlockAccuracy = 0;
		for (size_t row = 0; row < medicalRelevanceTestData.x.size(); ++row)
		{
			std::vector<bool> medicalRelevancePredictionsVector;
			for (size_t svmIndex = 0; svmIndex < medicalRelevanceSvmVector.size(); ++svmIndex)
			{
				medicalRelevancePredictionsVector.push_back(getLabel(medicalRelevanceTestData.x[row], medicalRelevanceSvmVector[svmIndex]));
			}

			//compute total votes for each cluster
			std::vector<unsigned short> clusterVotes = getTotalClusterVotes(medicalRelevancePredictionsVector, medicalRelevanceClusterCount);

			//determine cluster with maximum votes, if unique...
			medicalRelevancePredictions.emplace_back(evaluateMaximum(clusterVotes));

			medicalRelevanceBlockAccuracy += medicalRelevancePredictions.back() == medicalRelevanceTestData.clusterLabels[row] ? 1 : 0;

			std::cout << "Done " << row + 1 << " of " << medicalRelevanceTestData.x.size() << ". ";
			std::cout << "Expected medical relevance cluster: " << medicalRelevanceTestData.clusterLabels[row] << " ";
			std::cout << "Predicted medical relevance cluster: " << medicalRelevancePredictions.back() << std::endl;
		}

		std::cout << std::endl;

		//print medical relevance statistics
		std::cout << "Medical relevance block correct predictions: " << medicalRelevanceBlockAccuracy << " out of " << medicalRelevanceTestData.x.size() << "." << std::endl;
		std::cout << "Medical relevance block accuracy: " << (static_cast<double>(medicalRelevanceBlockAccuracy) / medicalRelevanceTestData.x.size()) * 100.0 << "%" << std::endl;
		std::cout << std::endl;

		//compute safety predictions and accuracy
		std::vector<std::vector<bool>> safetyPredictions;//false = negative; true = positive
		for (size_t svmIndex = 0; svmIndex < safetySvmVector.size(); ++svmIndex)
		{
			unsigned int falsePositives = 0;
			unsigned int falseNegatives = 0;

			//get an iterator to the corresponding test data
			std::map<std::string, std::shared_ptr<TestData>>::const_iterator testDataIterator = safetyBlockTestDataMap.find(safetySvmVector[svmIndex]->GetUnsafeClasses());

			if (safetyBlockTestDataMap.end() != testDataIterator)
			{
				std::vector<bool> safetyPredictionsVector;
				
				for (size_t row = 0; row < testDataIterator->second->x.size(); ++row)
				{
					//we're only interested in the sign of the prediction
					safetyPredictionsVector.push_back(getLabel(testDataIterator->second->x[row], safetySvmVector[svmIndex]));
					//debug
					//std::cout << safetyPredictionsVector.back() << std::endl;

					//unsafe label => the safety prediction must be negative (false)
					if (safetySvmVector[svmIndex].get()->ContainsLabel(testDataIterator->second->qualityOfLifeLabels[row]) && safetyPredictionsVector.back() == true)
						++falsePositives;
					//safe label => the safety prediction must be positive (true)
					else if (!safetySvmVector[svmIndex].get()->ContainsLabel(testDataIterator->second->qualityOfLifeLabels[row]) && safetyPredictionsVector.back() == false)
						++falseNegatives;
				}
				safetyPredictions.emplace_back(safetyPredictionsVector);
			}
			else
			{
				throw std::runtime_error("Missing safety test data for unsafe classes: " + safetySvmVector[svmIndex]->GetUnsafeClasses());
			}

			std::cout << "Done " << safetySvmVector[svmIndex].get()->GetModelFileName() << ". ";
			std::cout << "Correct predictions: " << testDataIterator->second->x.size() - (falsePositives + falseNegatives) << " out of " << testDataIterator->second->x.size() << "; ";
			std::cout << "False positives: " << falsePositives << "; ";
			std::cout << "False negatives: " << falseNegatives << "; ";
			std::cout << "Accuracy: " << (static_cast<double>(testDataIterator->second->x.size() - (falsePositives + falseNegatives)) / testDataIterator->second->x.size()) * 100.0 << "%." << std::endl;
		}

		std::cout << std::endl << "Kernel: " << kernel << std::endl;
		
		/*
		std::cout << "Safety block: " << std::endl;
		for (size_t svmIndex = 0; svmIndex < safetySvmVector.size(); ++svmIndex)
		{
			//get an iterator to the corresponding test data
			std::map<std::string, std::shared_ptr<TestData>>::const_iterator testDataIterator = safetyBlockTestDataMap.find(safetySvmVector[svmIndex]->GetUnsafeClasses());

			
		}
		*/
	}
	catch (const std::runtime_error &exception)
	{
		std::cout << exception.what() << std::endl;
	}

	return 0;
}