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
@file secure_recommendations/hub.h
@brief Definition of class Hub.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef HUB_HEADER_GUARD
#define HUB_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "utils/filesystem.h"
#include "utils/math.h"
#include "utils/date_time.h"
#include "utils/cpu_timer.h"
#include "core/big_integer.h"
#include "core/random_provider.h"
#include "core/paillier.h"

#include "server.h"
#include "test_data_row.h"

//include C++ libraries
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <numeric>
#include <vector>
#include <map>
#include <stdexcept>

namespace SeComLib {
using namespace Core;

namespace SecureRecommendations {
	//forward-declare required classes
	class Server;

	/**
	@brief Home hub client
	*/
	class Hub {
	public:
		/// Default constructor
		Hub ();

		/// Destructor - void implementation
		~Hub () {}

		/// Returns a reference to the public key
		const PaillierPublicKey &GetPublicKey () const;

		/// Sets a reference to the recommendations server
		void SetServer (const std::shared_ptr<const Server> &server);

		/// Secure sign evaluation
		void EvaluateSign (SecureSvm::EncryptedVector &input) const;

		/// Secure maximum evaluation
		void EvaluateMaximum (SecureSvm::EncryptedVector &input) const;

		/// Secure division evaluation
		void EvaluateDivision (const BigInteger &numerator, SecureSvm::EncryptedVector &input) const;

		/// Execute the accuracy analysis of the system
		void DoAccuracyAnalysis ();

		/// Execute the performance analysis of the system
		void DoPerformanceAnalysis ();

		/// Execute the traffic analysis of the system
		void DoTrafficAnalysis ();

		/// Decrypts and prints an encrypted value
		void DebugValue (const Paillier::Ciphertext &value) const;
	private:
		/// The crypto provider
		Paillier cryptoProvider;

		/// A reference to the recommendations server
		std::shared_ptr<const Server> server;

		/// Contains the number of vectors in the test data file.
		/// Since the homogeneous polynomial kernel does not need the x matrix, there should be a variable which maintains the number of elements so that its available for all kernel types.
		unsigned long testVectorCount;

		/// The number of attributes in each test vector of the test data
		unsigned int attributeCount;

		/// The SVM kernel type. We want to pre-compute only the data that is necessary for a particular kernel
		SecureSvm::KernelTypes kernel;

		/// The scaling applied to the test and model vectors @f$ x_i @f$ and @f$ s_i @f$
		BigInteger featureScalingFactor;

		/// The scaling applied to the SVM parameters, @f$ a_i @f$ and @f$ b @f$
		BigInteger svWeightScaling;

		/// The medical relevance block test data
		std::vector<TestDataRow> medicalRelevanceTestData;

		/// The safety block test data array (vector of collection of rows; each file should have the same number of rows)
		std::vector<std::map<std::string, TestDataRow>> safetyTestData;

		/// The predicted clusters
		std::vector<unsigned short> predictedClusters;

		/// Vector of predicted quality of life values (contains 0 for negative values and 1 for positive values)
		std::vector<std::vector<unsigned short>> predictedQualityOfLifeMatrix;

		/// Vector containing number of false positives per safety SVM
		std::map<std::string, unsigned int> safetyBlockFalsePositives;

		/// Vector containing number of false negatives per safety SVM
		std::map<std::string, unsigned int> safetyBlockFalseNegatives;

		/// Enables traffic profiling
		static bool measureTraffic;

		/// Counts the numbe of bits sent to the server
		static BigInteger bitsSent;

		/// Counts the number of bits received from the server
		static BigInteger bitsReceived;

		/// Populates the safetyTestData structure
		void loadSafetyTestData (const std::string &testFilesDirectory, const std::string &safetyTestFilesPrefix);

		/// Extracts test data from a single line
		TestDataRow parseTestDataRow (const std::string &line) const;

		/// Returns the cluster index, which corresponds to the maximum
		unsigned short getVotedCluster (const std::vector<Paillier::Ciphertext> &encryptedClusterVotes) const;

		/// Returns the processed predictions of the safety block SVMs
		std::vector<unsigned short> processSafetyPredictions (const std::vector<Paillier::Ciphertext> &encryptedSafetyPredictions) const;

		/// Computes the number of correct predictions of the medical relevance block
		unsigned int getMedicalRelevanceBlockCorrectPredictionCount () const;

		/// Computes the number of false negatives and false positives of the safety block
		void computeSafetyBlockFalsePredictions ();

		/// Resets the traffic counters
		static void resetTrafficCounters ();

		/// Returns a string containing the name of the kernel specified in the configuration file
		std::string getKernelName () const;

		/// Copy constructor - not implemented
		Hub (Hub const &);

		/// Copy assignment operator - not implemented
		Hub operator= (Hub const &);
	};
}//namespace SecureRecommendations
}//namespace SeComLib

#endif//HUB_HEADER_GUARD