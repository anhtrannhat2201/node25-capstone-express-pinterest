interface InterfaceLogin {
  email: string;
  mat_khau: string;
}

interface InterfaceUser extends InterfaceLogin {
  nguoi_dung_id: number;
  ho_ten: string;
  tuoi: number;
  anh_dai_dien?: string;
}

export type { InterfaceLogin, InterfaceUser };
