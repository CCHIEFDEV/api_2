<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Banners extends Model
{
    use HasFactory;

    protected $table = 'banners';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['cover','type','position','value','text','start_time','end_time','extra_field','status'];
}
