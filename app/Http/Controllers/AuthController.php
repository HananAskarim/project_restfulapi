<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Models\Customers;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class AuthController extends BaseController
{
    public function auth()
    {
        $authheader = request()->header('Authorization'); // basic xxxbase64encodexxx
        $keyauth    = substr($authheader, 6);    // hilangkan text basic

        $plainauth  = base64_decode($keyauth); // decode text info login
        $tokenauth  = explode(':', $plainauth); //pisahkan email:password

        $email      = $tokenauth[0]; //email
        $pass       = $tokenauth[1]; //password

        $data   = (new Customers())->newQuery()->where(['email'=>$email])->get([ 'id', 'first_name', 'last_name', 'email', 'password' ])->first();

        if($data == null){ // jika data customer tidak ditemukan
            return $this->out( status: 'Gagal', code: 404, error: ['Pengguna tidak ditemukan'],); //404 tidak ditemukan
        }else{ //jika data customer ditemukan

            if( Hash::check($pass, $data->password) ){ //cek jika paswword cocok maka

                $data->token = hash('sha256', Str::random(10)); //buat token untuk dikirim ke client
                unset($data->password); //hilangkan informasi password yang akan dikirim ke client
                $data->update(); //update token disimpan ke tabel customer

                return $this->out(data: $data, status: 'OK',);

            }else{ //jika password tidak cocok maka

                return $this->out( status: 'Gagal', code: 401, error: ['Anda tidak memiliki wewenang'], ); //401 unauthorized

            }
        }
    }
}
