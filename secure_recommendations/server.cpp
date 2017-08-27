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
@file secure_recommendations/server.cpp
@brief Implementation of class Server.
@details Medical recommendations server implementation
@author Mihai Todor (todormihai@gmail.com)
*/

#include "server.h"

namespace SeComLib {
namespace SecureRecommendations {
	/**
	Initializes the client's public key

	Precomputes required data

	@param key The client public key
	*/
	Server::Server (const PaillierPublicKey &key): cryptoProvider(key), clientPublicKey(key) {
		//set the kernel
		this->kernel = SecureSvm::GetKernel(Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.kernel"));

		//initialize other parameters
		this->contentItemCount = Utils::Config::GetInstance().GetParameter<unsigned int>("SecureRecommendations.Server.contentItemCount");
		this->blindingFactorSize = Utils::Config::GetInstance().GetParameter<unsigned int>("SecureRecommendations.Server.blindingFactorSize");
		this->modelFileExtension = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Server.modelFileExtension");

		/// Initialize the medical relevance SVM models parameters
		this->medicalRelevanceModelsDirectory = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Server.MedicalRelevanceBlock.svmModelsFolder") + Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.kernel") + "/";
		this->medicalRelevanceClusterCount = Utils::Config::GetInstance().GetParameter<unsigned int>("SecureRecommendations.Server.MedicalRelevanceBlock.clusters");

		/// Initialize the safety SVM models parameters
		this->safetyModelsDirectory = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Server.SafetyBlock.svmModelsFolder") + Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.kernel") + "/";

		/// Precompute [0] and [1] for optimization purposes
		this->encryptedZero = this->cryptoProvider.GetEncryptedZero();
		this->encryptedOne = this->cryptoProvider.GetEncryptedOne();
	}

	/**
	Associates the server with the client instance

	@param client a client instance
	*/
	void Server::SetClient (const std::shared_ptr<const Hub> &client) {
		this->client = client;
	}

	/**
	This method needs to be called first!

	Loads the medical relevance and the safety SVMs.

	Generates dummy data for the content items, the preferences block and the safety block.
	*/
	void Server::Initialize () {
		std::cout << "Preprocessing model files data." << std::endl;

		/// Load medical relevance block SVMs
		this->loadMedicalRelevanceSvmModels(this->medicalRelevanceModelsDirectory);

		std::cout << "Finished preprocessing data from " << this->medicalRelevanceSvms.size() << " medical relevance block model files." << std::endl;

		/// Load safety block SVMs
		this->loadSafetySvmModels(this->safetyModelsDirectory);

		std::cout << "Finished preprocessing data from " << this->safetySvms.size() << " safety block model files." << std::endl;

		/// Generate a dummy vector of content items with values from 0 to 10 and scale them with 10.
		for (unsigned int i = 0; i < this->contentItemCount; ++i) {
			this->dummyContentItems.emplace_back((RandomProvider::GetInstance().GetRandomInteger(BigInteger(9)) + 1) * 10);
		}

		std::cout << "Finished generating dummy content items." << std::endl;

		/// Generate a dummy vector of encrypted preferences block scores with values from 1 to 10.
		/// @todo Is the range really from 1 to 10 or is it 0 to 10?
		for (unsigned int i = 0; i < this->contentItemCount; ++i) {
			this->dummyEncryptedPreferenceScores.emplace_back(this->cryptoProvider.EncryptInteger(RandomProvider::GetInstance().GetRandomInteger(BigInteger(9) + 1)));
		}

		std::cout << "Finished generating dummy preferences block scores." << std::endl;
	}

	/**
	Blinds each denominator multiplicatively with a factor @f$ r_i @f$, such that it does not generate overflows.

	Permutes all the denominators randomly.

	Sends the permuted vector of blinded denominators to the client and receives the results of @f$ 1 / d_i @f$.

	Undoes the random permutation and homomorphically multiplies each result by @f$ r_i @f$, in order to get the desired values.

	@param numerator the value of the numerator
	@param denominators vector of encrypted denominators. Will be overwritten by the kernel values
	*/
	void Server::InteractiveSecureDivision (const BigInteger &numerator, SecureSvm::EncryptedVector &denominators) const {
		std::vector<BigInteger> blindingFactors;

		/// Blind the encrypted denominators. Store the blinding factors.
		for (size_t i = 0; i < denominators.size(); ++i) {
			/// @f$ r_i @f$ must always be > 0!
			blindingFactors.emplace_back(RandomProvider::GetInstance().GetRandomInteger(this->blindingFactorSize) + 1);

			//blind the encrypted denominators
			denominators[i] = denominators[i] * blindingFactors.back();
		}

		/// Get a random permutation
		SecurePermutation permutation(denominators.size());
		
		/// Permute the blinded encrypted denominators.
		permutation.Permute(denominators);

		/// Interact with the client
		this->client.lock()->EvaluateDivision(numerator, denominators);

		/// Reverse the permutation
		permutation.InvertPermutation(denominators);

		/// Undo the blinding
		for (size_t i = 0; i < denominators.size(); ++i) {
			//debug kernel values
			//this->client.lock()->DebugValue(denominators[i]);

			denominators[i] = denominators[i] * blindingFactors[i];
		}
	}

	/**
	Determines the cluster with the highest number of votes.

	Given N, the number of clusters, for each cluster we must perform binary clasification and then sum the votes for each cluster.
	The cluster having the highest number of votes is determined with an interactive protocol.

	Evaluates the safety block SVMs.

	@param clusterVotes returns a vector containing [1] at the index of the cluster with the maximum number of votes and [0] everywhere else
	@param safetyPredictions returns a vector which, for each safety SVM, contains [1] if the SVM produced a positive value and [0] otherwise
	@param medicalRelevanceTestData the medical relevance test data
	@param safetyTestData the safety test data
	@throw Missing safety test data
	*/
	void Server::GetAccuracyPredictions (Server::EncryptedClusterVotes &clusterVotes, SecureSvm::EncryptedVector &safetyPredictions, const TestDataRow &medicalRelevanceTestData, const std::map<std::string, TestDataRow> &safetyTestData) const {
		//container for the SVM predictions (both medical relevance and safety)
		Server::EncryptedSvmValues svmPredictions;

		/// First, we evaluate all the medical relevance SVMs
		
		for (size_t i = 0; i < this->medicalRelevanceSvms.size(); ++i) {
			//debug
			//std::string start = Utils::DateTime::Now();
			svmPredictions.emplace_back(this->medicalRelevanceSvms[i]->Predict(medicalRelevanceTestData.x, medicalRelevanceTestData.xx, medicalRelevanceTestData.xSquared));
			//std::cout << "medical" << i << ": "; this->client.lock()->DebugValue(svmPredictions.back());
			//std::cout << "start: " << start << " end: " << Utils::DateTime::Now() << " SVM: " << i << std::endl;
		}
		
		/// We also evaluate the safety SVMs (we will pop these out later, because we want to perform the interactive sign evaluation in a single step)
		for (size_t i = 0; i < this->safetySvms.size(); ++i) {
			std::map<std::string, TestDataRow>::const_iterator safetyTestDataIterator = safetyTestData.find(safetySvms[i]->GetUnsafeClasses());
			if (safetyTestData.end() != safetyTestDataIterator) {
				//debug
				//std::string start = Utils::DateTime::Now();
				svmPredictions.emplace_back(this->safetySvms[i]->Predict((*safetyTestDataIterator).second.x, (*safetyTestDataIterator).second.xx, (*safetyTestDataIterator).second.xSquared));
				//std::cout << safetyTestDataIterator->first << ": "; this->client.lock()->DebugValue(svmPredictions.back());
				//std::cout << "start: " << start << " end: " << Utils::DateTime::Now() << " SVM: " << i << " nSV: " << this->safetySvms[i]->model->l << std::endl;
			}
			else {
				/// @todo Throw a custom exception here...
				throw std::runtime_error("Missing safety test data for unsafe classes: " + safetySvms[i]->GetUnsafeClasses());
			}
		}

		/// Ask the client to determine the sign with an interactive secure permutation algorithm, such that for each value we will contain either [0] or [1]
		
		//overwrite the svmPredictions with the data received from the client
		this->interactiveSignEvaluation(svmPredictions);

		//debug
		/*
		for (size_t i = 0; i < svmPredictions.size(); ++i) {
			this->client.lock()->DebugValue(svmPredictions[i]);
		}
		*/

		//extract and remove the safety SVM predictions from the svmPredictions vector
		std::move(svmPredictions.begin() + this->medicalRelevanceSvms.size(), svmPredictions.end(), std::back_inserter(safetyPredictions)); 
		svmPredictions.erase(svmPredictions.begin() + this->medicalRelevanceSvms.size(), svmPredictions.end());

		/// Compute the total number of votes for each cluster (we add the elements on each column together)
 		clusterVotes = this->getTotalClusterVotes(svmPredictions);

		/// Ask the client to evaluate the cluster with the maximum number of votes
		/// The results vector will contain [1] at the index of the maximum and [0] at the other indexes
		
		//overwrite the clusterVotes variable
		this->interactiveMaximumEvaluation(clusterVotes);
	}

	/**
	Evaluates the output of the first two blocks:
	- Produces a vecor of sum_j(dummyEncryptedContentItems[i] * vote[j])
	- Adds the above vector homomorphically to the dummyEncryptedPreferenceScores and obtains the firstTwoBlocksPredictions
	- Sets the first 5 elements of the dummyEncryptedSafetyScores to the value obtained by evaluating the safety SVM

	@param firstTwoBlocksPredictions returns a vector containing the combined predictions of the first two blocks
	@param safetyPredictions returns a vector which, for each safety SVM, contains [1] if the SVM produced a positive value and [0] otherwise
	@param medicalRelevanceTestData the medical relevance test data
	@param safetyTestData the safety test data
	*/
	void Server::GetPerformancePredictions (SecureSvm::EncryptedVector &firstTwoBlocksPredictions, SecureSvm::EncryptedVector &safetyPredictions, const TestDataRow &medicalRelevanceTestData, const std::map<std::string, TestDataRow> &safetyTestData) const {
		Server::EncryptedClusterVotes clusterVotes;

		/// Evaluate the medical relevance votes and the safety prediction
		this->GetAccuracyPredictions(clusterVotes, safetyPredictions, medicalRelevanceTestData, safetyTestData);

		/// Compute the outptut of the first two blocks
		for (unsigned long i = 0; i < this->contentItemCount; ++i) {
			//initialize the accumulator
			Paillier::Ciphertext result = this->encryptedZero;

			for (unsigned long j = 0; j < this->medicalRelevanceClusterCount; ++j) {
				//multiply the content items with the cluster votes and add the products
				result = result + clusterVotes[j] * this->dummyContentItems[i];
			}

			//combine the medical relevance and the preferences block
			firstTwoBlocksPredictions.emplace_back(result + this->dummyEncryptedPreferenceScores[i]);
		}
	}

	/**
	@return a vector containing the set of unsafe classes for each safety SVM
	*/
	std::vector<std::string> Server::GetSafetyBlockSvmsUnsafeClasses () const {
		std::vector<std::string> output;

		for (size_t i = 0; i < this->safetySvms.size(); ++i) {
			output.emplace_back(this->safetySvms[i]->GetUnsafeClasses());
		}

		return output;
	}

	/**
	@return a vector containing the names of the model files for the safety block
	*/
	std::deque<std::string> Server::GetSafetyBlockModelFiles () const {
		return this->safetySvmModelFiles;
	}
	
	/**
	@param value the value to debug
	*/
	void Server::DebugValue (const Paillier::Ciphertext &value) const {
		this->client.lock()->DebugValue(value);
	}

	/**
	The SVMs are binary classifiers between two clusters.

	Since the SVMs are symmetric (@f$ SVM_{jvi} = 1 - SVM_{ivj} @f$), we only load the ones where @f$ i < j @f$

	@param modelsDirectory the path to the medical relevance SVM models directory
	*/
	void Server::loadMedicalRelevanceSvmModels (const std::string &modelsDirectory) {
		for (unsigned int i = 0; i < this->medicalRelevanceClusterCount; ++i) {
			for (unsigned int j = i + 1; j < this->medicalRelevanceClusterCount; ++j) {
				std::stringstream fileNameBuilder;

				//construct the file path
				fileNameBuilder << "cluster" << (i + 1) << "v" << (j + 1) << "." + this->modelFileExtension;
				
				//std::unique_ptr ensures that the SecureSvm objects will not get passed by value
				this->medicalRelevanceSvms.emplace_back(std::unique_ptr<SecureSvm>(new SecureSvm(modelsDirectory, fileNameBuilder.str(), this->clientPublicKey, shared_from_this())));
			}
		}
	}

	/**
	@param modelsDirectory the path to the safety SVM models directory
	*/
	void Server::loadSafetySvmModels (const std::string &modelsDirectory) {
		this->safetySvmModelFiles = Utils::Filesystem::GetFilesInDirectory(modelsDirectory);

		/// @todo Throw a custom error.
		if (safetySvmModelFiles.empty()) {
			throw std::runtime_error("No model files found in directory: " + modelsDirectory);
		}

		for (std::deque<std::string>::const_iterator fileIterator = safetySvmModelFiles.begin(); fileIterator != safetySvmModelFiles.end(); ++fileIterator) {
			//std::unique_ptr ensures that the SecureSvm objects will not get passed by value
			this->safetySvms.emplace_back(std::unique_ptr<SecureSvm>(new SecureSvm(modelsDirectory, *fileIterator, this->clientPublicKey, shared_from_this())));
		}
		
	}

	/**
	@param votes a vector containing the encrypted values predicted by the SVMs
	@return Vector containing the votes for each cluster
	*/
	Server::EncryptedClusterVotes Server::getTotalClusterVotes (EncryptedSvmValues &votes) const {
		Server::EncryptedClusterVotes clusterVotes;

		/// We want to compute the sum of elements on each column, so we iterate over the lines in the inner loop
		for (unsigned int i = 0; i < this->medicalRelevanceClusterCount; ++i) {
			//initialize the vote accumulator to [0]
			clusterVotes.emplace_back(this->encryptedZero);

			for (unsigned int j = 0; j < this->medicalRelevanceClusterCount; ++j) {
				/// We computed only the SVM predictions for cluster(i, j), where i < j, because for i > j, prediction(i, j) = 1 - prediction(j, i)

				//the upper right triangle of the prediction values matrix is stored as an unraveled vector
				//basically, we need to subtract sum(i - 1) = (i - 1) * i / 2 at each step to determine the index in the vector
				//also, we subtract (i + 1) at each step because we need to account for the missing SVM(i, i) values
				unsigned int index;
				
				//we don't have SVM(i, i)
				if (i != j) {
					//upper right triangle
					if (i < j) {
						index = i * (medicalRelevanceClusterCount - 1) - (i - 1) * i / 2 + j - (i + 1);

						clusterVotes[i] = clusterVotes[i] + votes[index];
					}
					else {
						index = j * (medicalRelevanceClusterCount - 1) - (j - 1) * j / 2 + i - (j + 1);

						//prediction(i, j) = 1 - prediction(j, i)
						clusterVotes[i] = clusterVotes[i] + this->encryptedOne - votes[index];
					}
				}
			}//i
		}//j

		return clusterVotes;
	}

	/**
	Overwrites the input data with a vector of votes ([0] or [1]) for each value in the input vector.

	Permutes the values.

	Multiplicatively blinds the values: @f$ [f_i(x)]^{r_i} @f$.
	
	Calls the client's EvaluateSign method.

	Reverses the permutation.

	@param data a vector containing the encypted values predicted by the SVMs
	*/
	void Server::interactiveSignEvaluation (Server::EncryptedSvmValues &data) const {
		/// Get a random permutation
		SecurePermutation permutation(data.size());
		
		/// Permute the input vector
		permutation.Permute(data);

		/// Multiplicatively blind the values with a random factor @f$ r @f$
		for (Server::EncryptedSvmValues::iterator encryptedSvmValue = data.begin(); encryptedSvmValue != data.end(); ++encryptedSvmValue) {
			//this operation may cause an overflow on the plaintext data if the random number ends up being too large
			*encryptedSvmValue = *encryptedSvmValue * RandomProvider::GetInstance().GetRandomInteger(this->blindingFactorSize);
		}

		/// Interact with the client
		this->client.lock()->EvaluateSign(data);

		/// Reverse the permutation
		permutation.InvertPermutation(data);
	}

	/**
	Overwrites the input data with a vector containing [1] at the location of the maximum and [0] everywhere else.

	Permutes the values.

	Blinds the values multiplicatively and additively @f$ [w_i r_1 + r_2] = [w_i]^{r_1} r_2 @f$.
	
	Calls the client's EvaluateMaximum method.

	Reverses the permutation.

	@param data a vector of encrypted cluster votes
	*/
	void Server::interactiveMaximumEvaluation (Server::EncryptedClusterVotes &data) const {
		/// Get a random permutation
		SecurePermutation permutation(data.size());
		
		/// Permute the input vector
		permutation.Permute(data);

		/// Multiplicatively blind the values with a random factor @f$ r_1 > 0 @f$
		BigInteger r1 = RandomProvider::GetInstance().GetRandomInteger(this->blindingFactorSize) + 1;
		/// Additively blind the values with a random factor @f$ r_2 @f$
		Paillier::Ciphertext r2 = this->cryptoProvider.EncryptInteger(RandomProvider::GetInstance().GetRandomInteger(this->blindingFactorSize));

		for (Server::EncryptedClusterVotes::iterator encryptedClusterVote = data.begin(); encryptedClusterVote != data.end(); ++encryptedClusterVote) {
			//this operation may cause an overflow on the plaintext data if the random number ends up being too large
			*encryptedClusterVote = *encryptedClusterVote * r1 + r2;
		}

		/// Interact with the client
		this->client.lock()->EvaluateMaximum(data);

		/// Reverse the permutation
		permutation.InvertPermutation(data);
	}

}//namespace SecureRecommendations
}//namespace SeComLib