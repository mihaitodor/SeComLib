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
@file secure_recommendations/hub.cpp
@brief Implementation of class Hub.
@details Home hub client implementation
@author Mihai Todor (todormihai@gmail.com)
*/

#include "hub.h"

namespace SeComLib {
namespace SecureRecommendations {
	/**
	Disable traffic analysys by thefault
	*/
	bool Hub::measureTraffic(false);

	/**
	Initialize the sent bits counter
	*/
	BigInteger Hub::bitsSent(0);

	/**
	Initialize the received bits counter
	*/
	BigInteger Hub::bitsReceived(0);

	/**
	Initializes the test vector counter (not all kernels require the x matrix, so wee need to keep track of the number of est vectors)

	Generates the crypto provider keys.

	Initializes the private members with the configuration data.

	Pre-processes the test data.
	*/
	Hub::Hub () {
		/// Generate keys
		this->cryptoProvider.GenerateKeys();

		/// Set the kernel
		this->kernel = SecureSvm::GetKernel(Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.kernel"));

		/// Enable traffic measurements
		Hub::measureTraffic = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.analysisType") == "traffic" ? true : false;

		// Get configuration parameters
		this->attributeCount = Utils::Config::GetInstance().GetParameter<unsigned int>("SecureRecommendations.Hub.attributeCount");
		//we assume that all test files have the same number of entries
		this->testVectorCount = Utils::Config::GetInstance().GetParameter<unsigned int>("SecureRecommendations.Hub.testVectorCount");
		this->featureScalingFactor = BigInteger(10).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("SecureRecommendations.Svm.minimumFeatureDecimalDigits"));
		this->svWeightScaling = BigInteger(10).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("SecureRecommendations.Svm.minimumAiDecimalDigits"));

		//set the input test files paths
		std::string testFilesDirectory = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Hub.testFilesDirectory");
		std::string medicalRelevanceTestFile = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Hub.medicalRelevanceTestFile");
		std::string safetyTestFilesPrefix = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Hub.safetyTestFilesPrefix");

		std::cout << "Pre-processing test data files." << std::endl;

		//create a file stream to the medical relevance test file
		std::ifstream fileStream(testFilesDirectory + medicalRelevanceTestFile);

		//make sure the file exists and it is readable
		if (!fileStream.good()) {
			/// @todo Throw a custom exception here
			throw std::runtime_error("Can't open the medical relevance test file.");
		}
		
		std::string line;
		unsigned int lineCounter = 0;
		//iterate over all the lines in the medical relevance test file and populate the medicalRelevanceTestData structure
		while (std::getline(fileStream, line)) {
			this->medicalRelevanceTestData.emplace_back(this->parseTestDataRow(line));
			++lineCounter;
		}
		//sanity check
		if (lineCounter != this->testVectorCount) {
			/// @todo Throw a custom error.
			throw std::runtime_error("Unexpected number of test vectors detected in: " + testFilesDirectory + medicalRelevanceTestFile);
		}

		//load the medical safety test data
		this->loadSafetyTestData(testFilesDirectory, safetyTestFilesPrefix);

		std::cout << "Finished pre-processing test data files." << std::endl;
	}

	/**
	@return a reference to the public key
	*/
	const PaillierPublicKey &Hub::GetPublicKey () const {
		return this->cryptoProvider.GetPublicKey();
	}

	/**
	Associates the hub with the server instance

	@param server a server instance
	*/
	void Hub::SetServer (const std::shared_ptr<const Server> &server) {
		this->server = server;
	}

	/**
	Implements step 2 of the interactive secure comparison protocol.

	Replaces the contents of input with @f$ [1] @f$ if @f$ input[i] \geq 0 @f$ or @f$ [0] @f$ otherwise

	@param input the encrypted SVM values
	*/
	void Hub::EvaluateSign (SecureSvm::EncryptedVector &input) const {
		for (size_t i = 0; i < input.size(); ++i) {
			if (this->measureTraffic) {
				Hub::bitsReceived += static_cast<unsigned long>(input[i].data.GetSize());
			}

			/// Decrypt the value
			BigInteger decryptedValue = this->cryptoProvider.DecryptInteger(input[i]);
			
			/// Populate the vector received from the server with RE-RANDOMIZED [0]s and [1]s
			if (decryptedValue >= 0) {
				input[i] = this->cryptoProvider.GetEncryptedOne();
			}
			else {
				input[i] = this->cryptoProvider.GetEncryptedZero();
			}

			if (this->measureTraffic) {
				Hub::bitsSent += static_cast<unsigned long>(input[i].data.GetSize());
			}
		}
	}

	/**
	Implements step 2 of the interactive secure maximum evaluation protocol

	Replaces the contents of input with [1] at the location of the maximum and [0] everywhere else.

	If the maximum value is detected multiple times, consider that the prediction is wrong by default and return a vector of [0]

	@param input the encrypted number ov votes for each cluster
	*/
	void Hub::EvaluateMaximum (SecureSvm::EncryptedVector &input) const {
		if (this->measureTraffic) {
			for (SecureSvm::EncryptedVector::const_iterator i = input.begin(); i != input.end(); ++i) {
				Hub::bitsReceived += static_cast<unsigned long>((*i).data.GetSize());
			}
		}

		/// Set the maximum as the first value
		BigInteger maximum = this->cryptoProvider.DecryptInteger(input[0]);
		//store the index of the maximum value
		size_t index = 0;
		//set the fist value to [0] (we'll update it later to [1], if this turns out to be the real maximum)
		input[0] = this->cryptoProvider.GetEncryptedZero();//do not precompute this!

		//detect if the maximum value occurs more than once in the input data
		bool uniqueMaximumValue = true;

		/// Compare maximum with the other values to determine the real maximum
		for (size_t i = 1; i < input.size(); ++i) {
			//decrypt the current value
			BigInteger value = this->cryptoProvider.DecryptInteger(input[i]);

			if (maximum == value) {
				uniqueMaximumValue = false;
			}
			else if (maximum < value) {
				maximum = value;
				index = i;
				uniqueMaximumValue = true;//reset this flag if we update the maximum
			}

			//set all the values to [0]
			input[i] = this->cryptoProvider.GetEncryptedZero();//do not precompute this!
		}

		// Set [1] at the index where the first occurence of the maximum was found, but only if the maximum is unique
		if (uniqueMaximumValue) input[index] = this->cryptoProvider.GetEncryptedOne();//do not precompute this!

		if (this->measureTraffic) {
			for (SecureSvm::EncryptedVector::const_iterator i = input.begin(); i != input.end(); ++i) {
				Hub::bitsSent += static_cast<unsigned long>((*i).data.GetSize());
			}
		}
	}

	/**
	Implements step 2 of the interactive secure division protocol.

	Decrypts the received denominators, computes @f$ 1 / D_i @f$, reencrypts and sets the results back in the input vector.

	@param numerator the value of the numerator
	@param input the encrypted denominators. Will be overwritten by the encrypted results of the division
	*/
	void Hub::EvaluateDivision (const BigInteger &numerator, SecureSvm::EncryptedVector &input) const {
		/// Perform division
		for (size_t i = 0; i < input.size(); ++i) {
			if (this->measureTraffic) {
				Hub::bitsReceived += static_cast<unsigned long>(input[i].data.GetSize());
			}

			input[i] = this->cryptoProvider.EncryptInteger(numerator / this->cryptoProvider.DecryptInteger(input[i]));

			if (this->measureTraffic) {
				Hub::bitsSent += static_cast<unsigned long>(input[i].data.GetSize());
			}
		}
	}

	/**
	Sends each test vector to the server to obtain the recommendations and computes the accuracy of the received data.

	Prints statistic information.

	@throw std::runtime_error invalid kernel type
	*/
	void Hub::DoAccuracyAnalysis () {
		std::cout << std::endl << Utils::DateTime::Now() << ": Starting accuracy analysis with " << this->getKernelName() << std::endl << std::endl;
		std::cout << "Feature scaling factor: " << this->featureScalingFactor.ToString(10) << std::endl;
		std::cout << "Support vector weights scaling factor: " << this->svWeightScaling.ToString(10) << std::endl << std::endl;
		
		for (unsigned long i = 0; i < this->testVectorCount; ++i) {
			Server::EncryptedClusterVotes encryptedClusterVotes;
			SecureSvm::EncryptedVector encryptedSafetyPredictions;
			this->server->GetAccuracyPredictions(encryptedClusterVotes, encryptedSafetyPredictions, this->medicalRelevanceTestData[i], this->safetyTestData[i]);

			//extract the predicted cluster
			this->predictedClusters.emplace_back(this->getVotedCluster(encryptedClusterVotes));

			//compute the predicted quality of life values
			this->predictedQualityOfLifeMatrix.emplace_back(this->processSafetyPredictions(encryptedSafetyPredictions));

			std::cout << Utils::DateTime::Now() << ": Done " << i + 1 << " of " << this->testVectorCount
				<< ". Expected cluster: " << this->medicalRelevanceTestData[i].clusterLabel << ". Predicted cluster: " << this->predictedClusters.back() << std::endl;
		}

		/// Print statistics
		unsigned int medicalRelevanceBlockcorrectPredictions = this->getMedicalRelevanceBlockCorrectPredictionCount();
		std::cout << "Medical relevance block correct predictions: " << medicalRelevanceBlockcorrectPredictions << " out of " << this->testVectorCount << "." << std::endl;
		std::cout << "Medical relevance block accuracy: " << (static_cast<double>(medicalRelevanceBlockcorrectPredictions) / static_cast<double>(this->testVectorCount)) * 100.0 << "%" << std::endl;

		std::cout << "Safety block: " << std::endl;
		this->computeSafetyBlockFalsePredictions();

		for (std::map<std::string, unsigned int>::const_iterator falsePositivesIterator = this->safetyBlockFalsePositives.begin(), falseNegativesIterator = this->safetyBlockFalseNegatives.begin(); 
				falsePositivesIterator != this->safetyBlockFalsePositives.end(), falseNegativesIterator != this->safetyBlockFalseNegatives.end();
				++falsePositivesIterator, ++falseNegativesIterator) {
			std::cout << "Done " << falsePositivesIterator->first << ". ";
			std::cout << "Correct predictions: " << this->testVectorCount - (falsePositivesIterator->second + falseNegativesIterator->second) << " out of " << this->testVectorCount << "; ";
			std::cout << "False positives: " << falsePositivesIterator->second << "; ";
			std::cout << "False negatives: " << falseNegativesIterator->second << "; ";
			std::cout << "Accuracy: " << (static_cast<double>(this->testVectorCount - (falsePositivesIterator->second + falseNegativesIterator->second)) / static_cast<double>(this->testVectorCount)) * 100.0 << "%." << std::endl;
		}

		std::cout << std::endl << Utils::DateTime::Now() << ": Analysis complete." << std::endl;
	}

	/**
	Sends each test vector to the server to obtain the recommendations of the first two blocks and the third one.

	Performs the performance analysis of the algorithm.

	Prints statistic information.

	@throw std::runtime_error invalid kernel type
	*/
	void Hub::DoPerformanceAnalysis () {
		std::cout << std::endl << Utils::DateTime::Now() << ": Starting performance analysis with " << this->getKernelName() << std::endl << std::endl;
		std::cout << "Feature scaling factor: " << this->featureScalingFactor.ToString(10) << std::endl;
		std::cout << "Support vector weights scaling factor: " << this->svWeightScaling.ToString(10) << std::endl << std::endl;

		/// Store the processing time for each input vector
		std::vector<Utils::CpuTimer::NanosecondType> durationVector;

		/// Start the main timer
		Utils::CpuTimer mainTimer;
		for (unsigned long i = 0; i < this->testVectorCount; ++i) {
			//create local variables
			SecureSvm::EncryptedVector firstTwoBlocksPredictions;
			SecureSvm::EncryptedVector safetyBlockPredictions;

			//start the timer
			Utils::CpuTimer timer;

			this->server->GetPerformancePredictions(firstTwoBlocksPredictions, safetyBlockPredictions, this->medicalRelevanceTestData[i], this->safetyTestData[i]);

			/// Simulate client decryption and processing of the received data (but do not store it...)
			for (size_t j = 0; j < firstTwoBlocksPredictions.size(); ++j) {
				if (this->measureTraffic) {
					Hub::bitsReceived += static_cast<unsigned long>(firstTwoBlocksPredictions[j].data.GetSize()) + static_cast<unsigned long>(safetyBlockPredictions[j].data.GetSize());
				}

				this->cryptoProvider.DecryptInteger(firstTwoBlocksPredictions[j]) * this->cryptoProvider.DecryptInteger(safetyBlockPredictions[j]);
			}

			/// Store the duration for processing one input vector
			durationVector.emplace_back(timer.GetDuration());

			std::cout << "Done " << i + 1 << " of " << this->testVectorCount << " in " << Utils::CpuTimer::ToString(durationVector.back()) << std::endl;
		}

		/// Print statistics
		std::cout << "Entire process duration: " << mainTimer.ToString()<< std::endl;

		//compute minimum and maximum durations
		Utils::CpuTimer::NanosecondType minimum = durationVector[0];
		Utils::CpuTimer::NanosecondType maximum = durationVector[0];
		
		//start from 1
		for (size_t i = 1; i < this->testVectorCount; ++i) {
			if (minimum > durationVector[i]) minimum = durationVector[i];
			if (maximum < durationVector[i]) maximum = durationVector[i];
		}

		std::cout << "Per test vector statistics: " << std::endl;
		std::cout << "Minimum duration: " << Utils::CpuTimer::ToString(minimum) << std::endl;
		std::cout << "Maximum duration: " << Utils::CpuTimer::ToString(maximum) << std::endl;
		
		long double mean = static_cast<double>(std::accumulate(durationVector.begin(), durationVector.end(), 0)) / static_cast<double>(durationVector.size());
		std::cout << "Average duration: " << Utils::CpuTimer::ToString(static_cast<Utils::CpuTimer::NanosecondType>(mean)) << std::endl;
		long double standardDeviation = std::sqrt(static_cast<double>(std::inner_product(durationVector.begin(), durationVector.end(), durationVector.begin(), 0)) / static_cast<double>(durationVector.size()) - mean * mean);
		std::cout << "Standard deviation (in nanoseconds): " << Utils::CpuTimer::ToString(static_cast<Utils::CpuTimer::NanosecondType>(standardDeviation)) << std::endl;

		std::cout << std::endl << Utils::DateTime::Now() << ": Analysis complete." << std::endl;
	}

	/**
	Sends each test vector to the server to obtain the recommendations of the first two blocks and the third one.

	Performs the traffic analysis of the algorithm.

	Prints statistic information.

	@throw std::runtime_error invalid kernel type
	*/
	void Hub::DoTrafficAnalysis () {
		std::cout << std::endl << Utils::DateTime::Now() << ": Starting traffic analysis with " << this->getKernelName() << std::endl << std::endl;
		std::cout << "Feature scaling factor: " << this->featureScalingFactor.ToString(10) << std::endl;
		std::cout << "Support vector weights scaling factor: " << this->svWeightScaling.ToString(10) << std::endl << std::endl;

		this->resetTrafficCounters();
		BigInteger totalBitsSent;
		BigInteger totalBitsReceived;
		for (unsigned long i = 0; i < this->testVectorCount; ++i) {
			//create local variables
			SecureSvm::EncryptedVector firstTwoBlocksPredictions;
			SecureSvm::EncryptedVector safetyBlockPredictions;

			/// In a real scenario, we only have a single test data file, so we don't want to count the medical safety test files
			if (this->measureTraffic) {
				for (SecureSvm::EncryptedVector::const_iterator i = this->medicalRelevanceTestData.back().x.begin(); i != this->medicalRelevanceTestData.back().x.end(); ++i)
					Hub::bitsSent += static_cast<unsigned long>((*i).data.GetSize());
				for (SecureSvm::EncryptedVector::const_iterator i = this->medicalRelevanceTestData.back().xx.begin(); i != this->medicalRelevanceTestData.back().xx.end(); ++i)
					Hub::bitsSent += static_cast<unsigned long>((*i).data.GetSize());
				for (SecureSvm::EncryptedVector::const_iterator i = this->medicalRelevanceTestData.back().xSquared.begin(); i != this->medicalRelevanceTestData.back().xSquared.end(); ++i)
					Hub::bitsSent += static_cast<unsigned long>((*i).data.GetSize());
			}

			this->server->GetPerformancePredictions(firstTwoBlocksPredictions, safetyBlockPredictions, this->medicalRelevanceTestData[i], this->safetyTestData[i]);

			for (size_t j = 0; j < firstTwoBlocksPredictions.size(); ++j) {
				Hub::bitsReceived += static_cast<unsigned long>(firstTwoBlocksPredictions[j].data.GetSize()) + static_cast<unsigned long>(safetyBlockPredictions[j].data.GetSize());
			}

			totalBitsSent += Hub::bitsSent;
			totalBitsReceived += Hub::bitsReceived;
			std::cout << "Done " << i + 1 << " of " << this->testVectorCount << "; Bits sent: " << Hub::bitsSent.ToString(10) << "; Bits received: " << Hub::bitsReceived.ToString(10) << std::endl;
			this->resetTrafficCounters();
		}

		std::cout << "Total Bits sent: " << totalBitsSent.ToString(10) << std::endl;
		std::cout << "Total Bits received: " << totalBitsReceived.ToString(10) << std::endl;

		std::cout << std::endl << Utils::DateTime::Now() << ": Analysis complete." << std::endl;
	}

	/**
	@param value an encrypted value
	*/
	void Hub::DebugValue (const Paillier::Ciphertext &value) const {
		std::cout << this->cryptoProvider.DecryptInteger(value).ToString(10) << std::endl;
	}

	/**
	Populates the safetyTestData structure.

	@param testFilesDirectory the directory of the test files
	@param safetyTestFilesPrefix the prefix of the safety test files name
	@throw std::runtime_error can't find test files
	*/
	void Hub::loadSafetyTestData (const std::string &testFilesDirectory, const std::string &safetyTestFilesPrefix) {
		//build a list of safety test files
		std::deque<std::string> safetyTestFiles = Utils::Filesystem::GetFilesInDirectory(testFilesDirectory);

		if (safetyTestFiles.empty()) {
			/// @todo Throw a custom error.
			throw std::runtime_error("No files found in directory: " + testFilesDirectory);
		}

		//resize the safety test data container accordingly
		this->safetyTestData.resize(this->testVectorCount);

		for (std::deque<std::string>::const_iterator fileIterator = safetyTestFiles.begin(); fileIterator != safetyTestFiles.end(); ++fileIterator) {
			//there may be other files in the folder
			if (std::string::npos != (*fileIterator).find(safetyTestFilesPrefix)) {
				//each file name ends with a series of digits, which represent the unsafe classes
				//we want to extract and sort them in ascending order (just to be sure)
				//iterate over each class (digit) in the file name
				std::vector<unsigned short> unsafeClasses;
				for (size_t i = (*fileIterator).find_last_not_of("0123456789") + 1; i < (*fileIterator).size(); ++i) {
					//the difference between any digit and '0' will yield the desired numeric value
					unsafeClasses.emplace_back((*fileIterator)[i] - '0');
				}
				std::sort(unsafeClasses.begin(), unsafeClasses.end());

				//convert the ordered unsafeClasses vector to a stringstream
				std::stringstream unsafeClassesStream;
				for (std::vector<unsigned short>::const_iterator unsafeClassesIterator = unsafeClasses.begin(); unsafeClassesIterator != unsafeClasses.end(); ++unsafeClassesIterator) {
					unsafeClassesStream << *unsafeClassesIterator;
				}

				//create a file stream to the medical relevance test file
				std::ifstream fileStream(testFilesDirectory + *fileIterator);

				//make sure the file exists and it is readable
				if (!fileStream.good()) {
					/// @todo Throw a custom exception here
					throw std::runtime_error("Can't open the safety test file.");
				}
		
				std::string line;
				unsigned int lineCounter = 0;
				//iterate over all the lines in the file and populate the safetyTestData structure column by column
				while (std::getline(fileStream, line)) {
					this->safetyTestData[lineCounter][unsafeClassesStream.str()] = this->parseTestDataRow(line);
					++lineCounter;
				}

				//sanity check
				if (lineCounter != this->testVectorCount) {
					/// @todo Throw a custom error.
					throw std::runtime_error("Unexpected number of test vectors detected in: " + testFilesDirectory + *fileIterator);
				}
			}
		}
	}

	/**
	Populates a TestDataRow container.

	@param line a line from a test data file
	@return An instance of the TestDataRow container
	@throw std::runtime_error various line parsing errors
	*/
	TestDataRow Hub::parseTestDataRow (const std::string &line) const {
		TestDataRow output;

		/// Since g++ does not yet support std::regex properly, we'll have to extract the input data the old fashioned way...

		std::string::size_type hashPosition = line.find('#');
		std::string::size_type clPosition = line.find("cl");
		std::string::size_type qolPosition = line.find("qol");
		std::string::size_type genPosition = line.find("gen");
		if (std::string::npos == hashPosition || std::string::npos == clPosition || std::string::npos == qolPosition || std::string::npos == genPosition) {
			throw std::runtime_error("Label(s) not found in input file.");
		}
			
		std::string::size_type clQolDelimiter = line.find(' ', clPosition);
		std::string::size_type qolGenDelimiter = line.find(' ', qolPosition);
	
		if (std::string::npos == clQolDelimiter || std::string::npos == qolGenDelimiter) {
			throw std::runtime_error("Labels should be delimited by a space character.");
		}
			
		/// Use std::istringstream to manipulate the label data
		std::istringstream clusterLabel(line.substr(clPosition + 3, clQolDelimiter));
		//the input line should end after the qol value
		std::istringstream qualityOfLifeLabel(line.substr(qolPosition + 4, qolGenDelimiter));
		//we're not interested in the gen label

		if (!clusterLabel || !qualityOfLifeLabel) {
			throw std::runtime_error("Malformed labels detected in input file.");
		}

		unsigned short labelValue;

		/// Parse label data and persist it in our internal vectors.
			
		//the input test data indexes the clusters starting from 1.
		clusterLabel >> labelValue;
		if (labelValue < 1 || labelValue > 5) {
			throw std::runtime_error("Invalid cluster label.");
		}
		output.clusterLabel = labelValue;

		qualityOfLifeLabel >> labelValue;
		/// If the SVM result is negative, then the label must be contained in the model file name (valid values: 0-6) for correct predictions
		if (labelValue > 6) {
			throw std::runtime_error("Invalid quality of life label.");
		}
		//convert from unsigned short to char
		output.qualityOfLifeLabel = static_cast<char>('0' + labelValue);

		/// Build a vector of attributes
		std::vector<BigInteger> tempX;
			
		/// Extract the attribute values.
		/// Each attribute is stored as index:value, where index >= 1.
		/// We assume that each input line does not omit any attribute value (if it's 0), even though libsvm accepts this, so we simply discard the attribute indexes.
		std::string::size_type attributeValueStartPosition = line.find(':');
		if (std::string::npos == attributeValueStartPosition) {
			throw std::runtime_error("Can't find the first attribute.");
		}
		for (unsigned int i = 0; i < this->attributeCount; ++i) {
			std::string::size_type attributeDelimiterPosition = line.find(' ', attributeValueStartPosition);
			if (std::string::npos == attributeDelimiterPosition) {
				throw std::runtime_error("Input line does not contain the required number of attributes.");
			}
				
			//extract the current attribute value to stringstream so that we can convert it easily to double
			std::istringstream attributeStream(line.substr(attributeValueStartPosition + 1, attributeDelimiterPosition - attributeValueStartPosition - 1));
				
			if (!attributeStream) {
				throw std::runtime_error("Invalid attribute value detected.");
			}
				
			//std::cout << attributeStream.str() << std::endl;

			//convert stream to double (are 8 bytes / 15 digits enough???)
			double attribute;
			attributeStream >> attribute;

			//apply scaling
			//in case of negative values, remap them at the end of the key space
			tempX.push_back(BigInteger(attribute, this->featureScalingFactor));
				
			//jump to the next attribute
			attributeValueStartPosition = line.find(':', attributeValueStartPosition + 1);
		}

		//xx and xSqared matrices are required only for polynomial and rbf kernels
		if (SecureSvm::inverseQuadraticRBF == this->kernel || SecureSvm::homogeneousPolynomial == this->kernel || SecureSvm::inhomogeneousPolynomial == this->kernel) {
			for (unsigned int i = 0; i < tempX.size(); ++i) {
				//xx matrix is required only for polynomial kernels
				if (SecureSvm::homogeneousPolynomial == this->kernel || SecureSvm::inhomogeneousPolynomial == this->kernel) {
					for (unsigned int j = i; j < tempX.size(); ++j) {
						/// Polynomial kernel => need to send the encrypted attributes combinations, @f$ x_i x_j @f$, of the test vector, stored as an unraveled upper triangular matrix
						output.xx.push_back(this->cryptoProvider.EncryptInteger(tempX[i] * tempX[j]));
					}
				}

				//xSquared matrix is required only for the rbf kernel
				if (SecureSvm::inverseQuadraticRBF == this->kernel) {
					/// RBF kernel => need to send the encrypted squared attributes of the test vector
					output.xSquared.push_back(this->cryptoProvider.EncryptInteger(tempX[i] * tempX[i]));
				}
			}
		}

		//x matrix is not required for the homogeneous polynomial kernel
		if (SecureSvm::homogeneousPolynomial != this->kernel) {
			for (unsigned int i = 0; i < tempX.size(); ++i) {
				output.x.emplace_back(this->cryptoProvider.EncryptInteger(tempX[i]));
			}
		}

		return output;
	}

	/**
	Iterates through the encrypted cluster votes vector and identifies the position which holds the value [1].

	The input test data cluster labels are indexed starting from 1. We return 0 if the maximum could not be determined.

	@param encryptedClusterVotes The encrypted cluster votes vector
	@return the index of the cluster containing the maximum number of votes. Return 0 if no maximum was found.
	*/
	unsigned short Hub::getVotedCluster (const std::vector<Paillier::Ciphertext> &encryptedClusterVotes) const {
		//return 0 if the maximum does not exist in the input vector
		unsigned short output = 0;

		BigInteger one(1);
		for (size_t i = 0; i < encryptedClusterVotes.size(); ++i) {
			if (one == this->cryptoProvider.DecryptInteger(encryptedClusterVotes[i])) {
				//the input test data cluster labels are indexed starting from 1
				output = static_cast<unsigned short>(i + 1);
				break;
			}
		}

		return output;
	}

	/**
	Decrypts the safety predictions received from the server.

	Compares the descryptions with the unsafe classes of each SVM to determine if the prediction matched the qol label of the test data.

	@param encryptedSafetyPredictions The encrypted safety block SVM predictions vector
	@return the decrypted safety block SVM predictions
	*/
	std::vector<unsigned short> Hub::processSafetyPredictions (const std::vector<Paillier::Ciphertext> &encryptedSafetyPredictions) const {
		std::vector<unsigned short> output;
		for (std::vector<Paillier::Ciphertext>::const_iterator prediction = encryptedSafetyPredictions.begin(); prediction != encryptedSafetyPredictions.end(); ++prediction) {
			//debug
			//DebugValue(*prediction);

			//we expect only 2 possible values: 0 (negative prediction) and 1 (pozitive prediction)
			output.emplace_back(this->cryptoProvider.DecryptInteger(*prediction).ToUnsignedLong() == 0 ? 0 : 1);
		}

		return output;
	}

	/**
	@return The number of correct predictions of the medical relevance block
	*/
	unsigned int Hub::getMedicalRelevanceBlockCorrectPredictionCount () const {
		unsigned int correctPredictions = 0;

		for (unsigned long i = 0; i < this->testVectorCount; ++i) {
			correctPredictions += this->predictedClusters[i] == this->medicalRelevanceTestData[i].clusterLabel ? 1 : 0;
		}

		return correctPredictions;
	}

	/**
	*/
	void Hub::computeSafetyBlockFalsePredictions () {
		std::vector<std::string> safetyBlockSvmsUnsafeClasses = this->server->GetSafetyBlockSvmsUnsafeClasses();
		std::deque<std::string> safetyBlockSvmsModelFiles = this->server->GetSafetyBlockModelFiles();

		//initialize the false positives and false negatives counters
		for (std::deque<std::string>::const_iterator modelFile = safetyBlockSvmsModelFiles.begin(); modelFile != safetyBlockSvmsModelFiles.end(); ++modelFile) {
			this->safetyBlockFalsePositives[*modelFile] = 0;
			this->safetyBlockFalseNegatives[*modelFile] = 0;
		}

		//do iterate over all the prediction rows and count the false positives and false negatives
		for (size_t testRowIndex = 0; testRowIndex < this->predictedQualityOfLifeMatrix.size(); ++testRowIndex) {
			for (size_t svmIndex = 0; svmIndex < safetyBlockSvmsUnsafeClasses.size(); ++svmIndex) {
				std::map<std::string, TestDataRow>::const_iterator safetyTestDataIterator = this->safetyTestData[testRowIndex].find(safetyBlockSvmsUnsafeClasses[svmIndex]);
				if (this->safetyTestData[testRowIndex].end() != safetyTestDataIterator) {
					//unsafe label => the safety prediction must be negative (= 0)
					if (std::string::npos != safetyBlockSvmsUnsafeClasses[svmIndex].find(safetyTestDataIterator->second.qualityOfLifeLabel) && 1 == this->predictedQualityOfLifeMatrix[testRowIndex][svmIndex]) {
						++this->safetyBlockFalsePositives[safetyBlockSvmsModelFiles[svmIndex]];
					}
					//safe label => the safety prediction must be positive (= 1)
					else if (std::string::npos == safetyBlockSvmsUnsafeClasses[svmIndex].find(safetyTestDataIterator->second.qualityOfLifeLabel) && 0 == this->predictedQualityOfLifeMatrix[testRowIndex][svmIndex]) {
						++this->safetyBlockFalseNegatives[safetyBlockSvmsModelFiles[svmIndex]];
					}
				}
				else {
					/// @todo Throw a custom exception here...
					throw std::runtime_error("Missing safety test data for unsafe classes: " + safetyBlockSvmsUnsafeClasses[svmIndex]);
				}
			}
		}
	}

	void Hub::resetTrafficCounters () {
		Hub::bitsSent = 0;
		Hub::bitsReceived = 0;
	}

	/**
	@return a string containing the name of the kernel
	@throw std::runtime_error invalid kernel type
	*/
	std::string Hub::getKernelName () const {
		std::string name;

		switch (this->kernel) {
			case SecureSvm::linear:
				name = "linear kernel";
				break;
			case SecureSvm::homogeneousPolynomial:
				name = "homogeneous polynomial kernel";
				break;
			case SecureSvm::inhomogeneousPolynomial:
				name = "inhomogeneous polynomial kernel";
				break;
			case SecureSvm::inverseQuadraticRBF:
				name = "inverse quadratic RBF kernel";
				break;
			default:
				/// @todo Throw a custom error here
				throw std::runtime_error("Invalid kernel type.");
		}

		return name;
	}

}//namespace SecureRecommendations
}//namespace SeComLib