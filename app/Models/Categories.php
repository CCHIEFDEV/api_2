<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Categories extends Model
{
    use HasFactory;

    protected $table = 'categories';

    public $timestamps = true; //by default timestamp false

    protected $fillable = ['name','title_color','url_slugs','order_id','cover','translations','extra_field','status'];

}
