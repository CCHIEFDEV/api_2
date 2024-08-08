<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Medias extends Model
{
    use HasFactory;

    protected $table = 'media';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['name','type','extra_field','status'];

}
