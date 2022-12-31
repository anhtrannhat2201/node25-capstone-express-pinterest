import { PrismaClient, Prisma } from '@prisma/client';
const prisma = new PrismaClient();

// import bcrypt
import bcrypt from 'bcrypt';

// import local config
import 'dotenv/config';

const userData: Prisma.nguoi_dungCreateInput[] = [
  {
    email: 'ayaka@hoyoverse.com',
    mat_khau: bcrypt.hashSync(
      'AyakaOfKamisato#2809',
      Number(process.env.BCRYPT_SALT)
    ),
    ho_ten: 'Kamisato Ayaka',
    tuoi: 16,
    anh_dai_dien:
      'https://cdn.sforum.vn/sforum/wp-content/uploads/2022/04/1158044.png',
  },
  {
    email: 'alice@prisma.io',
    mat_khau: bcrypt.hashSync('Alice$123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Alice n Wonderland',
    tuoi: 16,
    anh_dai_dien:
      'https://celebrationspress.com/wp-content/uploads/2018/03/032618Alice.jpg',
  },
  {
    email: 'bob@prisma.io',
    mat_khau: bcrypt.hashSync('Bobz#123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Bob',
    tuoi: 17,
    anh_dai_dien:
      'https://upload.wikimedia.org/wikipedia/commons/7/7c/Alice-bob-mallory.jpg',
  },
  {
    email: 'tom@gmail.com',
    mat_khau: bcrypt.hashSync('toM?1234', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Tom',
    tuoi: 5,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/tomandjerry/images/6/6b/Tom_%28Tom_and_Jerry_Chase%29.jpg',
  },
  {
    email: 'jerry@gmail.com',
    mat_khau: bcrypt.hashSync('jErry!123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Jerry',
    tuoi: 5,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/tomandjerry/images/e/ec/Kisspng-jerry-mouse-tom-cat-nibbles-tom-and-jerry-5afa8781629bc3.8019112615263681294039.png',
  },
  {
    email: 'oggy@prisma.io',
    mat_khau: bcrypt.hashSync('Oggy$123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Oggy',
    tuoi: 4,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/oggyandthecockroaches/images/d/d9/OGGY_PERSO.png',
  },
  {
    email: 'joey@gmail.com',
    mat_khau: bcrypt.hashSync('joEy@123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Joey',
    tuoi: 2,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/oggyandthecockroaches/images/b/b6/JOEY_PERSO.png',
  },
  {
    email: 'marky@prisma.io',
    mat_khau: bcrypt.hashSync('marKy%123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Marky',
    tuoi: 2,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/oggyandthecockroaches/images/7/71/MARKY_PERSO.png',
  },
  {
    email: 'deedee@gmail.com',
    mat_khau: bcrypt.hashSync('dEeDee&123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Dee Dee',
    tuoi: 2,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/oggyandthecockroaches/images/6/65/DEEDEE_PERSO.png',
  },
  {
    email: 'courage@gmail.com',
    mat_khau: bcrypt.hashSync('couRage*123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Courage',
    tuoi: 5,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/courage/images/4/46/New_Courage.png',
  },
  {
    email: 'blossom@gmail.com',
    mat_khau: bcrypt.hashSync('Blossom#123', Number(process.env.BCRYPT_SALT)),
    ho_ten: 'Blossom',
    tuoi: 10,
    anh_dai_dien:
      'https://static.wikia.nocookie.net/powerpuff/images/2/23/Blossom-pic.png/',
  },
];

const imagesData: Prisma.hinh_anhCreateInput[] = [
  {
    ten_hinh: 'Pizza Night',
    duong_dan:
      'https://www.kingarthurbaking.com/sites/default/files/styles/hero_lg/public/2021-09/pizza_night_hero_0.jpg',
    mo_ta: 'Pizza for Dinner',
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ten_hinh: 'Warm Breakfast',
    duong_dan:
      'https://img.delicious.com.au/RwCMQREL/del/2017/04/all-day-pan-cooked-breakfast-44610-2.jpg',
    mo_ta: 'A breakfast with all Vegetable you need',
    nguoi_dung: { connect: { nguoi_dung_id: 6 } },
  },
  {
    ten_hinh: 'Beautiful Mountain Landscape',
    duong_dan:
      'https://hips.hearstapps.com/hmg-prod.s3.amazonaws.com/images/alpe-di-siusi-sunrise-with-sassolungo-or-langkofel-royalty-free-image-1623254127.jpg',
    mo_ta: 'Oh~ Such a Beautiful Scenary',
    nguoi_dung: { connect: { nguoi_dung_id: 8 } },
  },
  {
    ten_hinh: 'The Ocean in Blue Deep',
    duong_dan:
      'https://images.fineartamerica.com/images/artworkimages/mediumlarge/2/deep-blue-ocean-hdere.jpg',
    mo_ta: 'What a deep blue scene',
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ten_hinh: 'Northern Light Aurora',
    duong_dan:
      'https://resources.arctickingdom.com/hubfs/Imported_Blog_Media/Igloo-BLL-Under-Aurora.jpg',
    mo_ta: "OMG~ It's beautiful",
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ten_hinh: 'The Opposite Traffic on Highway',
    duong_dan:
      'https://cdn.vox-cdn.com/thumbor/0ma2o-VojU7ZmJb1yTd3Mxg-l5g=/232x0:2999x2075/1200x800/filters:focal(232x0:2999x2075)/cdn.vox-cdn.com/uploads/chorus_image/image/44219366/72499026.0.0.jpg',
    mo_ta: 'I sight that will never be seen in Vietnam, for now',
    nguoi_dung: { connect: { nguoi_dung_id: 8 } },
  },
  {
    ten_hinh: 'Rest API Overview',
    duong_dan: 'https://vantien.net/wp-content/uploads/2021/02/Rest-API.png',
    mo_ta: 'Rest API. Easy right?',
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
  {
    ten_hinh: 'Container Vessel',
    duong_dan:
      'https://techhistorian.com/content/images/2022/07/history-of-container-ships-techhistorian-01.webp',
    mo_ta: "It's huge, see it for yourself",
    nguoi_dung: { connect: { nguoi_dung_id: 9 } },
  },
  {
    ten_hinh: "Suffing! Let's go",
    duong_dan:
      'https://cdn1.i-scmp.com/sites/default/files/images/methode/2016/05/18/fd7d1b8e-1be1-11e6-9777-749fedcc73f5_image_hires.JPG',
    mo_ta: "On a summer vacation, let's go suffing",
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ten_hinh: 'Hot Air Balloon',
    duong_dan:
      'https://www.daysoftheyear.com/wp-content/uploads/hot-air-balloon-day2.jpg',
    mo_ta: "It's hot, isn't it",
    nguoi_dung: { connect: { nguoi_dung_id: 6 } },
  },
  {
    ten_hinh: 'Metropolis',
    duong_dan:
      'https://metropolisvinhomes.com/wp-content/uploads/2019/02/phoi-canh-vinhomes-lieu-giai.jpg',
    mo_ta: "Ya~ It's Metroplis Baby",
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
  {
    ten_hinh: 'Moon Night',
    duong_dan: 'https://wallpaperaccess.com/full/1217251.jpg',
    mo_ta: 'Moon Night. A beautiful sight',
    nguoi_dung: { connect: { nguoi_dung_id: 7 } },
  },
];

const commentsData: Prisma.binh_luanCreateInput[] = [
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Hi. Nice day',
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Nice',
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'What a nice sight',
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Great to have it',
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Yay~ Finally',
    hinh_anh: { connect: { hinh_id: 5 } },
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'All the good things',
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Is it OK to be here',
    hinh_anh: { connect: { hinh_id: 11 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: "Let's go",
    hinh_anh: { connect: { hinh_id: 10 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'I can do this all day',
    hinh_anh: { connect: { hinh_id: 9 } },
    nguoi_dung: { connect: { nguoi_dung_id: 8 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Come back here',
    hinh_anh: { connect: { hinh_id: 9 } },
    nguoi_dung: { connect: { nguoi_dung_id: 7 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'To be a great night',
    hinh_anh: { connect: { hinh_id: 5 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'The ultimate Technique',
    hinh_anh: { connect: { hinh_id: 6 } },
    nguoi_dung: { connect: { nguoi_dung_id: 9 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'The television is on',
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 7 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: "Why it's so complicated",
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'To the infinity and beyond',
    hinh_anh: { connect: { hinh_id: 8 } },
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'How can we get there?',
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Is it OK to be here?',
    hinh_anh: { connect: { hinh_id: 11 } },
    nguoi_dung: { connect: { nguoi_dung_id: 8 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: "I know that it's the best to be in the rain",
    hinh_anh: { connect: { hinh_id: 7 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'How can it be like this?',
    hinh_anh: { connect: { hinh_id: 8 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'I was distinated for more',
    hinh_anh: { connect: { hinh_id: 6 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_binh_luan: new Date(Date.now()),
    noi_dung: 'Shall we take a stroke?',
    hinh_anh: { connect: { hinh_id: 10 } },
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
];

const saveImagesData: Prisma.luu_anhCreateInput[] = [
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 5 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 3 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 4 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 1 } },
    nguoi_dung: { connect: { nguoi_dung_id: 8 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 7 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 9 } },
    nguoi_dung: { connect: { nguoi_dung_id: 7 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 6 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 1 } },
    nguoi_dung: { connect: { nguoi_dung_id: 10 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 5 } },
    nguoi_dung: { connect: { nguoi_dung_id: 1 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 1 } },
    nguoi_dung: { connect: { nguoi_dung_id: 2 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 2 } },
    nguoi_dung: { connect: { nguoi_dung_id: 2 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 3 } },
    nguoi_dung: { connect: { nguoi_dung_id: 2 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 9 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 10 } },
    nguoi_dung: { connect: { nguoi_dung_id: 3 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 7 } },
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
  {
    ngay_luu: new Date(Date.now()),
    hinh_anh: { connect: { hinh_id: 4 } },
    nguoi_dung: { connect: { nguoi_dung_id: 5 } },
  },
];

const main = async () => {
  console.log(`Start seeding ...`);
  for (const u of userData) {
    const user = await prisma.nguoi_dung.create({
      data: u,
    });
    console.log(`Created user with id: ${user.nguoi_dung_id}`);
  }

  for (const img of imagesData) {
    const image = await prisma.hinh_anh.create({
      data: img,
    });
    console.log(`Create image with id: ${image.hinh_id}`);
  }

  for (const c of commentsData) {
    const comment = await prisma.binh_luan.create({
      data: c,
    });
    console.log(`Created comment with id: ${comment.binh_luan_id}`);
  }

  for (const s of saveImagesData) {
    const saveImage = await prisma.luu_anh.create({
      data: s,
    });
    console.log(
      `Saved image with hinh_id ${saveImage.hinh_id} and nguoi_dung_id ${saveImage.nguoi_dung_id}`
    );
  }
  console.log(`Seeding finished.`);
};

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
