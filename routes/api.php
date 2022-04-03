<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::get('/auth', [App\Http\Controllers\AuthController::class, 'auth']);
Route::get('/products', [\App\Http\Controllers\ProductController::class, 'findAll']);
Route::get('/products/{produk}', [\App\Http\Controllers\ProductController::class, 'findOne']);

Route::post('/orders', [\App\Http\Controllers\OrderController::class, 'store']);
Route::get('/orders', [\App\Http\Controllers\OrderController::class, 'findAll']);
Route::patch('/orders/{order}', [\App\Http\Controllers\OrderController::class, 'update']);
Route::delete('/orders/{order}', [\App\Http\Controllers\OrderController::class, 'delete']);