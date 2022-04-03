<?php

namespace App\Http\Middleware;

use App\Models\Customers;
use Closure;
use Illuminate\Http\Request;

class Authorization
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $token      = $request->header('token');
        $customer   = Customers::where('token', $token)->first();

        if( $customer == null || $token == ''){ //jika customer tidak ada atau token kosong
            //stop proses dan kirimkan response token invalid
            return response()->json([ 
                    'status' => 'Invalid', 
                    'data'  => null,
                    'error' => ['TOken invalid, unauthorized!']
                ],401 //status: 401 = unauthorized
            );
        }
        //simpan data customer
        $request->setUserResolver(function () use ($customer) {
            return $customer;
        });

        return $next($request); //lanjutkan proses berikutnya
    }
}
