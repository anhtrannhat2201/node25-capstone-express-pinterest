import Joi from 'joi';

// import local interface
import {
    InterfaceComment,
    InterfaceImage,
    InterfaceLogin,
    InterfaceUser,
} from '../types';

// import local constants
import generalConstant from '../constants/generalConstants';

const validators = {
    isNumber: Joi.number().required(),
    login: Joi.object<InterfaceLogin>({
        email: Joi.string().email().required(),
        mat_khau: Joi.string()
            .min(8)
            .pattern(generalConstant.passRegExp)
            .required()
            .messages({
                'string.pattern.base':
                    'Độ dài mật khẩu phải từ 8 ký tự (chứa ít nhất 1 ký tự số, 1 ký tự in hoa & 1 ký tự đặc biệt @$!%*#?&)',
            }),
    }),
    comment: Joi.object<InterfaceComment, true>({
        binh_luan_id: Joi.number(),
        nguoi_dung_id: Joi.number().required(),
        hinh_id: Joi.number().required(),
        ngay_binh_luan: Joi.string().isoDate().required(),
        noi_dung: Joi.string().min(1).required(),
    }),
    user: function () {
        return this.login.append<InterfaceUser>({
            nguoi_dung_id: Joi.number(),
            ho_ten: Joi.string().min(1).required(),
            tuoi: Joi.number().required(),
            anh_dai_dien: Joi.string(),
        });
    },
    createUser: function () {
        return this.user().fork('nguoi_dung_id', (item) => item.forbidden());
    },
    image: Joi.object<InterfaceImage>({
        ten_hinh: Joi.string().min(1).required(),
        duong_dan: Joi.string().min(1).required(),
        mo_ta: Joi.string().min(1).required(),
        nguoi_dung_id: Joi.number().required(),
    }),
};

export default validators;
