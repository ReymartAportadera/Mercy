-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 04, 2026 at 03:09 PM
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
  `ai_analysis` text DEFAULT NULL,
  `size` varchar(50) DEFAULT NULL,
  `explanation` text DEFAULT NULL,
  `threat_ratio` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `uploaded_file`
--

INSERT INTO `uploaded_file` (`id`, `filename`, `filepath`, `upload_time`, `status`, `hash`, `entropy`, `pattern_result`, `signature_status`, `threat_level`, `risk_score`, `risky_imports`, `ai_analysis`, `size`, `explanation`, `threat_ratio`) VALUES
(81, 'obfuscated_test.txt', 'static/uploads\\obfuscated_test.txt', '2026-04-25 23:51:15', 'Threat', '695a06431fbead4ef42e5a3a4517fd2fc38d9f31fc53ebf5106f00e22e9fa905', 5.11, 'Code Execution detected, Encoding detected', 'Code Execution detected, Encoding detected', 'Medium', 30, 'None', 'Based on the analysis, I would classify this file as suspicious. The detection of code execution and encoding patterns suggests potential malicious intent, but the lack of risky imports and a moderate risk score of 30/100 indicate that it may not be overtly malicious. Further analysis is recommended to determine the file\'s true nature.', NULL, NULL, NULL),
(82, 'persistence_test.txt', 'static/uploads\\persistence_test.txt', '2026-04-25 23:51:35', 'Safe', NULL, NULL, NULL, NULL, 'Low', 0, NULL, 'Based on the analysis, I would categorize this file as suspicious. The presence of a persistence mechanism, which allows the file to maintain its presence on the system, raises concerns about its intentions. However, the low risk score of 23/100 and lack of risky imports suggest that it may not be overtly malicious, warranting further investigation.', NULL, NULL, NULL),
(83, 'downloadable_for_vs_code_to_run_trustfile.txt', 'static/uploads\\downloadable_for_vs_code_to_run_trustfile.txt', '2026-04-27 00:28:41', 'Safe', 'f90ec7969b8e2ffe513dfb343ed52d5211031f052ec0e9134a1b800b2758d413', 4.86, 'No suspicious patterns', 'No signatures detected', 'Low', 0, 'None', 'Based on the provided analysis, this file appears to be safe. The low entropy score and lack of suspicious patterns or risky imports suggest that the file does not exhibit typical characteristics of malware. The risk score of 0/100 further reinforces this assessment, indicating a low likelihood of malicious activity.', NULL, NULL, NULL);

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

-- --------------------------------------------------------

--
-- Table structure for table `user_settings`
--

CREATE TABLE `user_settings` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `auto_scan_enabled` tinyint(1) DEFAULT NULL,
  `auto_scan_mode` varchar(20) DEFAULT NULL,
  `default_scan_types` varchar(100) DEFAULT NULL,
  `notify_on_threat` tinyint(1) DEFAULT NULL,
  `theme` varchar(20) DEFAULT NULL,
  `auto_quarantine` tinyint(1) DEFAULT 1,
  `max_file_size_mb` int(11) DEFAULT 100,
  `alert_sound` tinyint(1) DEFAULT 1,
  `notify_safe` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `user_settings`
--

INSERT INTO `user_settings` (`id`, `user_id`, `auto_scan_enabled`, `auto_scan_mode`, `default_scan_types`, `notify_on_threat`, `theme`, `auto_quarantine`, `max_file_size_mb`, `alert_sound`, `notify_safe`) VALUES
(1, 1, 0, 'single', 'heuristic,ai_analysis,virustotal', 1, 'dark', 1, 100, 1, 1);

-- --------------------------------------------------------

--
-- Table structure for table `vt_cache`
--

CREATE TABLE `vt_cache` (
  `file_hash` varchar(255) NOT NULL,
  `positives` int(11) DEFAULT 0,
  `total_engines` int(11) DEFAULT 0,
  `scan_date` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `vt_cache`
--

INSERT INTO `vt_cache` (`file_hash`, `positives`, `total_engines`, `scan_date`) VALUES
('01e00088861706c13398b2e98433f81f3d86d675740319de67297319fbff565d', 0, 75, '2026-04-29 00:50:14'),
('04c5b6e6347554ce375bfcdbb110eb9de698b5689809f7eb34ce2b18f9305ddd', 0, 75, '2026-04-29 00:50:49'),
('04d48d84653c14878b422a721b5f2e4e408333511673c6fb7c65c0e44819cde7', 0, 75, '2026-04-29 00:49:53'),
('1b874b9d1bcdb9109c0bd30cdac772da1222338d23e3082ec6c4abdb7a27e93e', 0, 75, '2026-04-29 00:49:23'),
('2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad', 54, 76, '2026-04-07 09:23:50'),
('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 55, 76, '2026-04-06 21:42:42'),
('2cb34aeb23442d7c5ae221108966770fa5731017f46fa4c792080e222c554324', 0, 76, '2026-04-07 09:17:24'),
('462995d4b981acffa46cc2b19d7b5f2810e83d733c165e8d398d67123725e137', 0, 75, '2026-04-27 00:51:51'),
('4d16cd637bcc8c4476f64b367105fb3edf5a8b1ec19f32473f19d4a5ef8ce2a9', 0, 75, '2026-04-29 00:41:28'),
('62ddae74360318fe9ac55cc4f52d1261f940026fd7dc1266b8f3b55da079f5e8', 0, 75, '2026-04-29 00:47:18'),
('67e37c98da6f4c07b84e270e6b2487100094b421811773aa2a29671cc208718c', 0, 75, '2026-04-29 00:43:19'),
('695a06431fbead4ef42e5a3a4517fd2fc38d9f31fc53ebf5106f00e22e9fa905', 0, 76, '2026-04-25 23:33:35'),
('6b8203d5094890212392ea54cdc8a1bfe7c8e751d55796fb93ef2d03f217aa87', 0, 75, '2026-04-29 00:42:13'),
('6ee15522684a6780c00f3cb837c8759303d03223429ec0d649bcee3053b1dabd', 0, 75, '2026-04-29 00:50:15'),
('80472280d1228f4c14734843cc8589630e59b927bd0d2691657dff86e73ce0a4', 0, 75, '2026-04-29 00:48:33'),
('863643a387f9659907efe33eff98b5898630b9bf4fdef82db5c5a47948dbce62', 0, 76, '2026-04-25 23:26:29'),
('93e479c93834a628533a1c640bbb747c2553683939be5186d17792cdedae49c4', 0, 76, '2026-04-25 23:06:35'),
('9dd50d14596c05c15b665f29d52ff66d8a80beff8cced30c63898a3f52ce5dc8', 0, 75, '2026-04-29 00:45:24'),
('af26d337cc930c150b15d0f95452ce48e23ee3c1049decd8d9d5700bb3ebbc04', 0, 76, '2026-04-07 05:19:03'),
('c73d6a317500181e7f4ce00798d0c2b8a7006e460d561e60b4fe81bcfca2979e', 0, 0, '2026-04-29 00:46:46'),
('cb35521af476bf2e354cd070069d02a0598f85716cdd0165f38ae4ef5e17e7be', 1, 76, '2026-04-07 01:27:23'),
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0, 75, '2026-04-29 00:40:47'),
('e5c1cb81d9f8325c8c37734c68aa6f4657e529a13d2bd4abee8e8f2cec6f6f19', 0, 75, '2026-04-29 00:48:02'),
('e5f586291bd3ec63e88918d127fb8966c41fd78e2ac26761630de6b39f1cdd68', 0, 75, '2026-04-29 00:50:04'),
('f90ec7969b8e2ffe513dfb343ed52d5211031f052ec0e9134a1b800b2758d413', 0, 75, '2026-04-27 00:28:51'),
('fa365941f51bd6a1b3232c635fc68386fd0716d8d0e0db2ea3e9ffc7b530ba8c', 0, 75, '2026-04-29 00:41:42');

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
-- Indexes for table `user_settings`
--
ALTER TABLE `user_settings`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `user_id` (`user_id`);

--
-- Indexes for table `vt_cache`
--
ALTER TABLE `vt_cache`
  ADD PRIMARY KEY (`file_hash`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `uploaded_file`
--
ALTER TABLE `uploaded_file`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=84;

--
-- AUTO_INCREMENT for table `user`
--
ALTER TABLE `user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `user_settings`
--
ALTER TABLE `user_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `user_settings`
--
ALTER TABLE `user_settings`
  ADD CONSTRAINT `user_settings_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
