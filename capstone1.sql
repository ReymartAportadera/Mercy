-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Apr 05, 2026 at 04:58 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `capstone1`
--

-- --------------------------------------------------------

--
-- Table structure for table `uploaded_file`
--

CREATE TABLE `uploaded_file` (
  `id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `filepath` varchar(255) NOT NULL,
  `upload_time` datetime DEFAULT current_timestamp(),
  `status` varchar(50) DEFAULT NULL,
  `hash` varchar(255) DEFAULT NULL,
  `entropy` float DEFAULT NULL,
  `pattern_result` varchar(255) DEFAULT NULL,
  `signature_status` varchar(255) DEFAULT NULL,
  `threat_level` varchar(50) DEFAULT NULL,
  `risk_score` int(11) DEFAULT NULL,
  `risky_imports` text DEFAULT NULL,
  `ai_analysis` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `uploaded_file`
--

INSERT INTO `uploaded_file` (`id`, `filename`, `filepath`, `upload_time`, `status`, `hash`, `entropy`, `pattern_result`, `signature_status`, `threat_level`, `risk_score`, `risky_imports`, `ai_analysis`) VALUES
(48, 'exfiltration_test.txt', 'static/uploads\\exfiltration_test.txt', '2026-04-05 20:12:30', 'Threat', '06f86c24b532fd554fa834aa17305e1d40426b41666ac2a972924ef069d499eb', 4.81, 'Network detected', 'Data Exfiltration', 'Medium', 36, 'None', 'Based on the provided analysis, I would classify this file as suspicious. The entropy score of 4.81 is relatively high, indicating a high degree of randomness, which can be a characteristic of malicious code. However, the lack of risky imports and a moderate risk score of 36/100 suggest that the file may not be overtly malicious, but rather warrants further investigation.'),
(49, 'high_entropy.txt', 'static/uploads\\high_entropy.txt', '2026-04-05 20:56:09', 'Safe', 'cd141f9fb170ce3619f585e1398d15a301f6bffaddeba86326324730cd707ff7', 3.95, 'No suspicious patterns', 'No signatures detected', 'Low', 0, 'None', 'Based on the provided analysis, this file appears to be safe. The low entropy score and lack of suspicious patterns or risky imports suggest that the file does not contain malicious code. The risk score of 0/100 further reinforces this assessment, indicating a low likelihood of malware presence.'),
(50, 'obfuscated_test.txt', 'static/uploads\\obfuscated_test.txt', '2026-04-05 20:57:10', 'Threat', '695a06431fbead4ef42e5a3a4517fd2fc38d9f31fc53ebf5106f00e22e9fa905', 5.11, 'Code Execution detected, Encoding detected', 'Code Execution detected, Encoding detected', 'Medium', 30, 'None', 'Based on the analysis, this file is suspicious due to the detection of code execution and encoding patterns, which are common techniques used by malware to evade detection. However, the lack of risky imports and a moderate risk score of 30/100 suggest that the file may not be overtly malicious. Further analysis is recommended to determine the file\'s true nature.'),
(51, 'persistence_test.txt', 'static/uploads\\persistence_test.txt', '2026-04-05 20:57:45', 'Safe', '93e479c93834a628533a1c640bbb747c2553683939be5186d17792cdedae49c4', 5.01, 'Persistence Mechanism', 'Persistence Mechanism', 'Low', 23, 'None', 'Based on the provided analysis, I would classify this file as suspicious. The presence of a persistence mechanism, which allows the file to maintain its presence on the system, raises concerns about its intentions. However, the low risk score of 23/100 and lack of risky imports suggest that it may not be overtly malicious, warranting further investigation to determine its true nature.'),
(52, 'shell_test.txt', 'static/uploads\\shell_test.txt', '2026-04-05 20:58:33', 'Threat', 'cb35521af476bf2e354cd070069d02a0598f85716cdd0165f38ae4ef5e17e7be', 4.99, 'System Command detected, Process Spawn detected, Network detected', 'System Command detected, Process Spawn detected, Network detected', 'Medium', 43, 'None', 'Based on the analysis, I would classify this file as suspicious. The detection of System Command and Process Spawn patterns, along with Network activity, indicates potential malicious behavior. However, the relatively low Risk Score of 43/100 and the absence of Risky Imports suggest that the file may not be overtly malicious, warranting further investigation to determine its true nature.'),
(53, 'suspicious_imports.py', 'static/uploads\\suspicious_imports.py', '2026-04-05 20:59:15', 'Threat', '2cb34aeb23442d7c5ae221108966770fa5731017f46fa4c792080e222c554324', 4.75, 'System Command detected, Network detected, Encoding detected', 'System Command detected, Network detected, Encoding detected', 'Critical', 100, 'os, subprocess, socket, requests', 'Based on the analysis, this file is highly likely to be malicious. The combination of a high risk score (100/100), detection of suspicious patterns such as system command, network, and encoding, and the presence of risky imports like os, subprocess, socket, and requests suggest that the file may be designed to execute system-level commands, establish network connections, and potentially download or upload malicious data.');

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

CREATE TABLE `user` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`id`, `username`, `email`, `password`) VALUES
(1, 'reymart', 'reymartaportadera@gmail.com', 'pbkdf2:sha256:1000000$ltcxPzG8BueiJMrX$426a2b5249641fece555ea63bb6619ee0bdc728c74aeb5584a14397f5796013d');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `uploaded_file`
--
ALTER TABLE `uploaded_file`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `user`
--
ALTER TABLE `user`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `uploaded_file`
--
ALTER TABLE `uploaded_file`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=54;

--
-- AUTO_INCREMENT for table `user`
--
ALTER TABLE `user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
