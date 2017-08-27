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
@file private_recommendations_data_packing/main.cpp
@brief Private Recommendations with data packing main entry point.
@details Simulation for "Generating Private Recommendations Efficiently Using Homomorphic Encryption and Data Packing", Zekeriya Erkin, Thijs Veugen, Tomas Toft, and Reginald L. Lagendijk, 2012
@author Mihai Todor (todormihai@gmail.com)
*/

#include "main.h"

/**
Application entry point.

Usage: Accepts one optional parameter: the full path to the configuration file. Otherwise, it tries to find "config.xml" in the current directory.

@param argc number of command line arguments
@param argv array containing the command line arguments
@return The process exit status
*/
int main (int argc, char *argv[]) {
	try {
		//the first command line parameter always contains the name of the application
		if (argc > 1) {
			//a custom configuration file was specified
			Utils::Config::SetConfigFile(std::string(argv[1]));
		}

		std::cout << Utils::DateTime::Now() << ": Starting simulation." << std::endl << std::endl;

		/// Initialize the servers
		std::shared_ptr<PrivacyServiceProvider> privacyServiceProvider = std::make_shared<PrivacyServiceProvider>();
		std::shared_ptr<ServiceProvider> serviceProvider = std::make_shared<ServiceProvider>(privacyServiceProvider->GetPaillierPublicKey(), privacyServiceProvider->GetDgkPublicKey());
		serviceProvider->SetPrivacyServiceProvider(privacyServiceProvider);
		privacyServiceProvider->SetServiceProvider(serviceProvider);

		std::cout << Utils::DateTime::Now() << ": Finished initializing servers." << std::endl << std::endl;

		//compute the initial packed sparse items
		Client client(serviceProvider, privacyServiceProvider, privacyServiceProvider->GetPaillierPublicKey());

		std::cout << Utils::DateTime::Now() << ": Finished encrypting client data." << std::endl << std::endl;

		serviceProvider->GenerateDummyDatabase(client.GetNormalizedScaledRatings());

		std::cout << Utils::DateTime::Now() << ": Finished computing [V_c] for every user." << std::endl << std::endl;

		serviceProvider->ComputeSimilarityValues(client.GetNormalizedScaledRatings());

		std::cout << Utils::DateTime::Now() << ": Finished computing the similarity values and Gamma." << std::endl << std::endl;

		serviceProvider->ComputeUserRecommendations(client.GetSparseRatings());

		std::cout << Utils::DateTime::Now() << ": Finished pre-computing recommendations for all users." << std::endl << std::endl;

		/// Get recommendations for all users
		client.ComputeRecommendations();

		std::cout << std::endl << Utils::DateTime::Now() << ": Finished simulation." << std::endl << std::endl;
	}
	catch (const std::runtime_error &exception) {
		std::cout << exception.what() << std::endl;
	}
	catch (const std::exception &exception) {
		std::cout << exception.what() << std::endl;
	}
	//it won't catch low level exceptions, like division by 0, produced by GMP...
	catch (...) {
		std::cout << "Unexpected exception occured." << std::endl;
	}
	
	return 0;
}