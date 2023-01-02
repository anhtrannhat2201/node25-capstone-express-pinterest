-- -------------------------------------------------------------
-- TablePlus 5.1.0(468)
--
-- https://tableplus.com/
--
-- Database: db_pinterest
-- Generation Time: 2023-01-02 13:27:32.1800
-- -------------------------------------------------------------


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


CREATE TABLE `binh_luan` (
  `binh_luan_id` int NOT NULL AUTO_INCREMENT,
  `nguoi_dung_id` int DEFAULT NULL,
  `hinh_id` int NOT NULL,
  `ngay_binh_luan` datetime(3) NOT NULL,
  `noi_dung` text COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`binh_luan_id`),
  KEY `binh_luan_indexes` (`nguoi_dung_id`,`hinh_id`),
  KEY `binh_luan_ibfk_2` (`hinh_id`),
  CONSTRAINT `binh_luan_ibfk_1` FOREIGN KEY (`nguoi_dung_id`) REFERENCES `nguoi_dung` (`nguoi_dung_id`) ON DELETE SET NULL ON UPDATE RESTRICT,
  CONSTRAINT `binh_luan_ibfk_2` FOREIGN KEY (`hinh_id`) REFERENCES `hinh_anh` (`hinh_id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `hinh_anh` (
  `hinh_id` int NOT NULL AUTO_INCREMENT,
  `ten_hinh` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `duong_dan` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `mo_ta` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `nguoi_dung_id` int NOT NULL,
  PRIMARY KEY (`hinh_id`),
  KEY `nguoi_dung_id` (`nguoi_dung_id`),
  CONSTRAINT `hinh_anh_ibfk_1` FOREIGN KEY (`nguoi_dung_id`) REFERENCES `nguoi_dung` (`nguoi_dung_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `luu_anh` (
  `nguoi_dung_id` int NOT NULL,
  `hinh_id` int NOT NULL,
  `ngay_luu` datetime(3) NOT NULL,
  PRIMARY KEY (`nguoi_dung_id`,`hinh_id`),
  KEY `hinh_id` (`hinh_id`),
  CONSTRAINT `luu_anh_ibfk_1` FOREIGN KEY (`nguoi_dung_id`) REFERENCES `nguoi_dung` (`nguoi_dung_id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `luu_anh_ibfk_2` FOREIGN KEY (`hinh_id`) REFERENCES `hinh_anh` (`hinh_id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `nguoi_dung` (
  `nguoi_dung_id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `mat_khau` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ho_ten` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `tuoi` int NOT NULL,
  `anh_dai_dien` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`nguoi_dung_id`),
  UNIQUE KEY `nguoi_dung_email_key` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `binh_luan` (`binh_luan_id`, `nguoi_dung_id`, `hinh_id`, `ngay_binh_luan`, `noi_dung`) VALUES
(1, 7, 2, '2022-12-11 06:27:51.044', 'Đã đến lúc phải hành động'),
(2, 7, 2, '2023-01-01 00:00:51.044', 'Đã đến lúc phải hành động 2');

INSERT INTO `hinh_anh` (`hinh_id`, `ten_hinh`, `duong_dan`, `mo_ta`, `nguoi_dung_id`) VALUES
(2, 'Everest!', 'https://cafebiz.cafebizcdn.vn/162123310254002176/2022/12/21/75xoeg543rbe7hdyacrsulxf6a-1671509075696921568194-1671587607675-16715876079332095414471.jpeg', 'Snow climbing', 7),
(3, 'Bling!', 'https://cafebiz.cafebizcdn.vn/162123310254002176/2022/12/21/75xoeg543rbe7hdyacrsulxf6a-1671509075696921568194-1671587607675-16715876079332095414471.jpeg', 'Bling', 3),
(4, 'Bix!', 'https://cafebiz.cafebizcdn.vn/162123310254002176/2022/12/21/75xoeg543rbe7hdyacrsulxf6a-1671509075696921568194-1671587607675-16715876079332095414471.jpeg', 'Bix', 2),
(5, 'bob!', 'https://cafebiz.cafebizcdn.vn/162123310254002176/2022/12/21/75xoeg543rbe7hdyacrsulxf6a-1671509075696921568194-1671587607675-16715876079332095414471.jpeg', 'bob', 6),
(6, 'BlobbB!', 'https://cafebiz.cafebizcdn.vn/162123310254002176/2022/12/21/75xoeg543rbe7hdyacrsulxf6a-1671509075696921568194-1671587607675-16715876079332095414471.jpeg', 'BlobbB', 6);

INSERT INTO `luu_anh` (`nguoi_dung_id`, `hinh_id`, `ngay_luu`) VALUES
(7, 2, '2023-01-01 00:00:51.044');

INSERT INTO `nguoi_dung` (`nguoi_dung_id`, `email`, `mat_khau`, `ho_ten`, `tuoi`, `anh_dai_dien`) VALUES
(1, 'Bloblob@heaven.com', '$2b$10$.6d6FqszWFpz/.uS4q0sYeoucbnfON3rdbBE8kYauPSfwN6YTZfui', 'Bloblob', 23, 'https://pbs.twimg.com/media/E4K6Q7-WQAQxvXs.jpg'),
(2, 'anhnhat@gmail.com', '$2b$10$.gztDxgLgTIobZ0AOg6zee/hao9H/vjznAAc4L0fBWMhnGIctdwe6', 'Kamisato Ayaka', 16, 'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png'),
(3, 'test@gmail.com', '$2b$10$kyaRWQE6Y0i7FZjoGGvKvOYs1vvgtn4fKbwqbfSyPgjK03foN8C6O', 'Xnxx', 16, 'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png'),
(4, 'nhatanh@gmail.com', '$2b$10$OjwZuQ6vsVbCwwJRZmUXPOvB/I.hZFGIXM6KvjCru59dJEzJAXoeO', 'nhatanh', 17, 'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png'),
(5, 'nhatanh123@gmail.com', '$2b$10$crKsXBMBAsqhSD/.mwLdRuy/ZswVQ2WFj0BVWCDsWJbi.82YAnQUm', 'nhatanh', 17, 'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png'),
(6, 'nhatanhBE@gmail.com', '$2b$10$7YuENBYfgdv58enH6g7/BujXaqZKnu.tXn/aB4Nu7vLSUFijz5M7G', 'nhatanh', 17, 'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png'),
(7, 'testBE@gmail.com', '$2b$10$mV1P7wxaKmgSJ9hdTeV9r.4N/l2NA19HLT0eBIsriufYxW11VWkBG', 'Nhat Anh', 22, 'https://i.pinimg.com/736x/4a/4c/29/4a4c29807499a1a8085e9bde536a570a.jpg');



/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;