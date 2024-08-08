<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\v1\Auth\AuthController;
use App\Http\Controllers\v1\CitiesController;
use App\Http\Controllers\v1\CategoriesController;
use App\Http\Controllers\v1\SubCategoriesController;
use App\Http\Controllers\v1\NewsController;
use App\Http\Controllers\v1\BannersController;
use App\Http\Controllers\v1\MediasController;
use App\Http\Controllers\v1\PagesController;
use App\Http\Controllers\v1\FlushController;
use App\Http\Controllers\v1\NewsLikesController;
use App\Http\Controllers\v1\SavedNewsController;
use App\Http\Controllers\v1\ContactsController;
use App\Http\Controllers\v1\OtpController;
use App\Http\Controllers\v1\NewsCommentsController;
use App\Http\Controllers\v1\FcmTokenController;
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

Route::get('/', function () {
    return [
        'app' => 'City Chief News',
        'version' => '1.0.0',
    ];
});

Route::prefix('/v1')->group(function(){
    Route::group(['namespace' => 'Auth'],function(){
        Route::post('auth/create_account',[AuthController::class,'register']);
        Route::post('auth/login',[AuthController::class,'login']);
        Route::post('auth/adminLogin',[AuthController::class,'adminLogin']);

        Route::post('auth/create_admin_account',[AuthController::class,'create_admin_account']);
    });

    Route::group(['middleware' => ['admin_auth','jwt.auth']],function(){
        Route::post('auth/admin_logout',[AuthController::class,'logout']);

        Route::get('users/getUsers',[AuthController::class,'getUsers']);
        Route::get('news/getDashboard', [NewsController::class, 'getDashboard']);

        // Cities Routes
        Route::get('cities/getAll', [CitiesController::class, 'getAll']);
        Route::post('cities/create', [CitiesController::class, 'save']);
        Route::post('cities/update', [CitiesController::class, 'update']);
        Route::post('cities/destroy', [CitiesController::class, 'delete']);
        Route::post('cities/getById', [CitiesController::class, 'getById']);

        // CategoriesController Routes
        Route::post('categories/create', [CategoriesController::class, 'save']);
        Route::post('categories/getById', [CategoriesController::class, 'getById']);
        Route::post('categories/update', [CategoriesController::class, 'update']);
        Route::post('categories/updateOrder', [CategoriesController::class, 'updateOrder']);
        Route::post('categories/destroy', [CategoriesController::class, 'delete']);
        Route::get('categories/getAll', [CategoriesController::class, 'getAll']);

        // SubCategoriesController Routes
        Route::post('sub_categories/create', [SubCategoriesController::class, 'save']);
        Route::post('sub_categories/getById', [SubCategoriesController::class, 'getById']);
        Route::post('sub_categories/update', [SubCategoriesController::class, 'update']);
        Route::post('sub_categories/destroy', [SubCategoriesController::class, 'delete']);
        Route::get('sub_categories/getAll', [SubCategoriesController::class, 'getAll']);
        Route::post('sub_categories/getByCate', [SubCategoriesController::class, 'getByCate']);

        // NewsController Routes
        Route::post('news/create', [NewsController::class, 'save']);
        Route::post('news/getById', [NewsController::class, 'getById']);
        Route::post('news/update', [NewsController::class, 'update']);
        Route::post('news/destroy', [NewsController::class, 'delete']);
        Route::get('news/getAll', [NewsController::class, 'getAll']);

        // BannersController Routes
        Route::post('banners/create', [BannersController::class, 'save']);
        Route::post('banners/getById', [BannersController::class, 'getById']);
        Route::post('banners/update', [BannersController::class, 'update']);
        Route::post('banners/destroy', [BannersController::class, 'delete']);
        Route::get('banners/getAll', [BannersController::class, 'getAll']);

        // MediasController
        Route::post('medias/create', [MediasController::class, 'save']);
        Route::post('medias/getById', [MediasController::class, 'getById']);
        Route::post('medias/update', [MediasController::class, 'update']);
        Route::post('medias/destroy', [MediasController::class, 'delete']);
        Route::get('medias/getAll', [MediasController::class, 'getAll']);

        // PagesController Routes
        Route::post('pages/getById', [PagesController::class, 'getById']);
        Route::get('pages/getAll', [PagesController::class, 'getAll']);
        Route::post('pages/update', [PagesController::class, 'update']);

        Route::post('flush/saveIt', [FlushController::class, 'saveIt']);
        Route::get('flush/getWebSettings', [FlushController::class, 'getWebSettings']);

        Route::get('users/authors',[AuthController::class,'authors']);
        Route::post('users/create_new_author',[AuthController::class,'create_new_author']);
        Route::post('users/deleteUser',[AuthController::class,'deleteUser']);
        Route::post('profile/update',[AuthController::class,'update']);
        Route::post('profile/getInfo',[AuthController::class,'getInfo']);

        Route::get('contacts/getAll',[ContactsController::class, 'getAll'] );
        Route::post('contacts/update',[ContactsController::class, 'update'] );
        Route::post('mails/replyContactForm',[ContactsController::class, 'replyContactForm']);

        Route::post('likes/getByNewsId', [NewsLikesController::class, 'getByNewsId']);
        Route::post('sendNoficationGlobal', [AuthController::class, 'sendNoficationGlobal']);
    });

    Route::group(['middleware' => ['user_auth','jwt.auth']],function(){
        Route::post('auth/logout',[AuthController::class,'logout']);

        Route::post('news/saveLike', [NewsLikesController::class,'save']);
        Route::post('news/deleteLike', [NewsLikesController::class,'delete']);

        Route::post('news/saveNews', [SavedNewsController::class,'save']);
        Route::post('news/deleteSaved', [SavedNewsController::class,'delete']);

        Route::post('news/getSavedNews', [SavedNewsController::class,'getSavedNews']);

        Route::post('comment/create', [NewsCommentsController::class, 'save']);
        Route::post('comment/getById', [NewsCommentsController::class, 'getById']);
        Route::post('comment/update', [NewsCommentsController::class, 'update']);
        Route::post('comment/destroy', [NewsCommentsController::class, 'delete']);
        Route::get('comment/getAll', [NewsCommentsController::class, 'getAll']);

    });

    Route::get('users/get_admin',[AuthController::class,'get_admin']);
    Route::post('uploadImage', [AuthController::class, 'uploadImage']);
    Route::post('uploadVideo', [AuthController::class, 'uploadVideo']);

    // Reset Password
    Route::post('users/emailExist', [AuthController::class, 'emailExist']);
    Route::post('otp/verifyOTP',[OtpController::class, 'verifyOTP'] );
    Route::post('updateUserPasswordWithEmail', [AuthController::class, 'updateUserPasswordWithEmail']);
    // Reset Password

    Route::post('pages/getContent', [PagesController::class, 'getById']);
    Route::get('categories/getCategoriesForUser', [CategoriesController::class, 'getCategoriesForUser']);
    Route::get('banners/userBanners', [BannersController::class, 'userBanners']);

    Route::post('users/getByCate', [NewsController::class, 'getByCate']);
    Route::post('news/getByNewsId', [NewsController::class, 'getByNewsId']);
    Route::post('news/getRelate', [NewsController::class, 'getRelate']);
    Route::post('contacts/create',[ContactsController::class, 'save'] );
    Route::post('sendMailToAdmin',[ContactsController::class, 'sendMailToAdmin']);

    Route::post('news/searchQuery', [NewsController::class, 'searchQuery']);
    Route::get('news/getVideoNews', [NewsController::class, 'getVideoNews']);

    Route::post('comment/getByNewsId', [NewsCommentsController::class, 'getByNewsId']);

    Route::get('news/getTopNews', [NewsController::class, 'getTopNews']);
    Route::post('saveToken', [FcmTokenController::class, 'saveToken']);
});
