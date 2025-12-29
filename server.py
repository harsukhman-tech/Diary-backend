from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# =============== MODELS ===============

# User Models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: Literal["Owner", "Manager", "Worker", "Accountant"]
    
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    role: Literal["Owner", "Manager", "Worker", "Accountant"]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User

# Animal Models
class AnimalCreate(BaseModel):
    tag_id: str
    animal_type: Literal["Cow", "Buffalo"]
    breed: str
    age_months: int
    purchase_price: float
    purchase_date: str
    daily_feed_kg: float = 0

class Animal(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tag_id: str
    animal_type: Literal["Cow", "Buffalo"]
    breed: str
    age_months: int
    purchase_price: float
    purchase_date: str
    daily_feed_kg: float
    status: Literal["Active", "Sold", "Died"] = "Active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Milk Production Models
class MilkProductionCreate(BaseModel):
    animal_id: str
    date: str
    morning_liters: float = 0
    evening_liters: float = 0
    fat_percentage: Optional[float] = None
    snf_percentage: Optional[float] = None

class MilkProduction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    animal_id: str
    date: str
    morning_liters: float
    evening_liters: float
    total_liters: float
    fat_percentage: Optional[float] = None
    snf_percentage: Optional[float] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Feed Models
class FeedInventoryCreate(BaseModel):
    feed_type: Literal["Green Fodder", "Dry Fodder", "Concentrate", "Other"]
    quantity_kg: float
    price_per_kg: float
    purchase_date: str

class FeedInventory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    feed_type: Literal["Green Fodder", "Dry Fodder", "Concentrate", "Other"]
    quantity_kg: float
    price_per_kg: float
    purchase_date: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Customer Models
class CustomerCreate(BaseModel):
    name: str
    phone: str
    address: Optional[str] = None
    daily_liters: float = 0
    price_per_liter: float = 0

class Customer(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    phone: str
    address: Optional[str] = None
    daily_liters: float
    price_per_liter: float
    balance: float = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Worker Models
class WorkerCreate(BaseModel):
    name: str
    phone: str
    role: str
    monthly_salary: float
    joining_date: str

class Worker(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    phone: str
    role: str
    monthly_salary: float
    joining_date: str
    advance_paid: float = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Expense Models
class ExpenseCreate(BaseModel):
    category: Literal["Feed", "Medicine", "Electricity", "Water", "Transport", "Maintenance", "Other"]
    amount: float
    description: str
    date: str

class Expense(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: Literal["Feed", "Medicine", "Electricity", "Water", "Transport", "Maintenance", "Other"]
    amount: float
    description: str
    date: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Sale Models
class SaleCreate(BaseModel):
    date: str
    customer_id: Optional[str] = None
    customer_name: str
    liters: float
    price_per_liter: float
    total_amount: float

class Sale(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    date: str
    customer_id: Optional[str] = None
    customer_name: str
    liters: float
    price_per_liter: float
    total_amount: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Health Record Models
class HealthRecordCreate(BaseModel):
    animal_id: str
    date: str
    record_type: Literal["Vaccination", "Disease", "Treatment", "Checkup"]
    description: str
    cost: float = 0

class HealthRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    animal_id: str
    date: str
    record_type: Literal["Vaccination", "Disease", "Treatment", "Checkup"]
    description: str
    cost: float
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# =============== AUTH FUNCTIONS ===============

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
        if user_doc is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        if isinstance(user_doc.get('created_at'), str):
            user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
        
        return User(**user_doc)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# =============== AUTH ROUTES ===============

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_input: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_input.email}, {"_id": 0})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_dict = user_input.model_dump()
    hashed_password = hash_password(user_dict.pop("password"))
    user_obj = User(**user_dict)
    
    doc = user_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['hashed_password'] = hashed_password
    
    await db.users.insert_one(doc)
    
    # Create token
    access_token = create_access_token(data={"sub": user_obj.id})
    
    return TokenResponse(access_token=access_token, user=user_obj)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user_doc = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user_doc or not verify_password(credentials.password, user_doc['hashed_password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if isinstance(user_doc.get('created_at'), str):
        user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
    
    user_obj = User(**{k: v for k, v in user_doc.items() if k != 'hashed_password'})
    access_token = create_access_token(data={"sub": user_obj.id})
    
    return TokenResponse(access_token=access_token, user=user_obj)

# =============== ANIMAL ROUTES ===============

@api_router.get("/animals", response_model=List[Animal])
async def get_animals(current_user: User = Depends(get_current_user)):
    animals = await db.animals.find({}, {"_id": 0}).to_list(1000)
    for animal in animals:
        if isinstance(animal.get('created_at'), str):
            animal['created_at'] = datetime.fromisoformat(animal['created_at'])
    return animals

@api_router.post("/animals", response_model=Animal)
async def create_animal(animal_input: AnimalCreate, current_user: User = Depends(get_current_user)):
    animal_obj = Animal(**animal_input.model_dump())
    doc = animal_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.animals.insert_one(doc)
    return animal_obj

@api_router.put("/animals/{animal_id}", response_model=Animal)
async def update_animal(animal_id: str, animal_input: AnimalCreate, current_user: User = Depends(get_current_user)):
    result = await db.animals.find_one({"id": animal_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Animal not found")
    
    update_data = animal_input.model_dump()
    await db.animals.update_one({"id": animal_id}, {"$set": update_data})
    
    updated = await db.animals.find_one({"id": animal_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    return Animal(**updated)

@api_router.delete("/animals/{animal_id}")
async def delete_animal(animal_id: str, current_user: User = Depends(get_current_user)):
    result = await db.animals.delete_one({"id": animal_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Animal not found")
    return {"message": "Animal deleted successfully"}

# =============== MILK PRODUCTION ROUTES ===============

@api_router.get("/milk-production", response_model=List[MilkProduction])
async def get_milk_production(current_user: User = Depends(get_current_user)):
    records = await db.milk_production.find({}, {"_id": 0}).to_list(1000)
    for record in records:
        if isinstance(record.get('created_at'), str):
            record['created_at'] = datetime.fromisoformat(record['created_at'])
    return records

@api_router.post("/milk-production", response_model=MilkProduction)
async def create_milk_production(milk_input: MilkProductionCreate, current_user: User = Depends(get_current_user)):
    milk_dict = milk_input.model_dump()
    milk_dict['total_liters'] = milk_dict['morning_liters'] + milk_dict['evening_liters']
    milk_obj = MilkProduction(**milk_dict)
    
    doc = milk_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.milk_production.insert_one(doc)
    return milk_obj

# =============== FEED ROUTES ===============

@api_router.get("/feed-inventory", response_model=List[FeedInventory])
async def get_feed_inventory(current_user: User = Depends(get_current_user)):
    feeds = await db.feed_inventory.find({}, {"_id": 0}).to_list(1000)
    for feed in feeds:
        if isinstance(feed.get('created_at'), str):
            feed['created_at'] = datetime.fromisoformat(feed['created_at'])
    return feeds

@api_router.post("/feed-inventory", response_model=FeedInventory)
async def create_feed_inventory(feed_input: FeedInventoryCreate, current_user: User = Depends(get_current_user)):
    feed_obj = FeedInventory(**feed_input.model_dump())
    doc = feed_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.feed_inventory.insert_one(doc)
    return feed_obj

# =============== CUSTOMER ROUTES ===============

@api_router.get("/customers", response_model=List[Customer])
async def get_customers(current_user: User = Depends(get_current_user)):
    customers = await db.customers.find({}, {"_id": 0}).to_list(1000)
    for customer in customers:
        if isinstance(customer.get('created_at'), str):
            customer['created_at'] = datetime.fromisoformat(customer['created_at'])
    return customers

@api_router.post("/customers", response_model=Customer)
async def create_customer(customer_input: CustomerCreate, current_user: User = Depends(get_current_user)):
    customer_obj = Customer(**customer_input.model_dump())
    doc = customer_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.customers.insert_one(doc)
    return customer_obj

@api_router.put("/customers/{customer_id}", response_model=Customer)
async def update_customer(customer_id: str, customer_input: CustomerCreate, current_user: User = Depends(get_current_user)):
    result = await db.customers.find_one({"id": customer_id}, {"_id": 0})
    if not result:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    update_data = customer_input.model_dump()
    await db.customers.update_one({"id": customer_id}, {"$set": update_data})
    
    updated = await db.customers.find_one({"id": customer_id}, {"_id": 0})
    if isinstance(updated.get('created_at'), str):
        updated['created_at'] = datetime.fromisoformat(updated['created_at'])
    return Customer(**updated)

# =============== WORKER ROUTES ===============

@api_router.get("/workers", response_model=List[Worker])
async def get_workers(current_user: User = Depends(get_current_user)):
    workers = await db.workers.find({}, {"_id": 0}).to_list(1000)
    for worker in workers:
        if isinstance(worker.get('created_at'), str):
            worker['created_at'] = datetime.fromisoformat(worker['created_at'])
    return workers

@api_router.post("/workers", response_model=Worker)
async def create_worker(worker_input: WorkerCreate, current_user: User = Depends(get_current_user)):
    worker_obj = Worker(**worker_input.model_dump())
    doc = worker_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.workers.insert_one(doc)
    return worker_obj

# =============== EXPENSE ROUTES ===============

@api_router.get("/expenses", response_model=List[Expense])
async def get_expenses(current_user: User = Depends(get_current_user)):
    expenses = await db.expenses.find({}, {"_id": 0}).to_list(1000)
    for expense in expenses:
        if isinstance(expense.get('created_at'), str):
            expense['created_at'] = datetime.fromisoformat(expense['created_at'])
    return expenses

@api_router.post("/expenses", response_model=Expense)
async def create_expense(expense_input: ExpenseCreate, current_user: User = Depends(get_current_user)):
    expense_obj = Expense(**expense_input.model_dump())
    doc = expense_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.expenses.insert_one(doc)
    return expense_obj

# =============== SALE ROUTES ===============

@api_router.get("/sales", response_model=List[Sale])
async def get_sales(current_user: User = Depends(get_current_user)):
    sales = await db.sales.find({}, {"_id": 0}).to_list(1000)
    for sale in sales:
        if isinstance(sale.get('created_at'), str):
            sale['created_at'] = datetime.fromisoformat(sale['created_at'])
    return sales

@api_router.post("/sales", response_model=Sale)
async def create_sale(sale_input: SaleCreate, current_user: User = Depends(get_current_user)):
    sale_obj = Sale(**sale_input.model_dump())
    doc = sale_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.sales.insert_one(doc)
    return sale_obj

# =============== HEALTH RECORD ROUTES ===============

@api_router.get("/health-records", response_model=List[HealthRecord])
async def get_health_records(animal_id: Optional[str] = None, current_user: User = Depends(get_current_user)):
    query = {"animal_id": animal_id} if animal_id else {}
    records = await db.health_records.find(query, {"_id": 0}).to_list(1000)
    for record in records:
        if isinstance(record.get('created_at'), str):
            record['created_at'] = datetime.fromisoformat(record['created_at'])
    return records

@api_router.post("/health-records", response_model=HealthRecord)
async def create_health_record(record_input: HealthRecordCreate, current_user: User = Depends(get_current_user)):
    record_obj = HealthRecord(**record_input.model_dump())
    doc = record_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.health_records.insert_one(doc)
    return record_obj

# =============== ANALYTICS ROUTES ===============

class DashboardStats(BaseModel):
    total_animals: int
    active_animals: int
    total_milk_today: float
    total_revenue_month: float
    total_expenses_month: float
    profit_loss_month: float
    total_customers: int
    total_workers: int

@api_router.get("/analytics/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    # Get today's date and current month
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")
    
    # Total and active animals
    all_animals = await db.animals.find({}, {"_id": 0}).to_list(1000)
    total_animals = len(all_animals)
    active_animals = len([a for a in all_animals if a.get('status') == 'Active'])
    
    # Today's milk production
    today_milk = await db.milk_production.find({"date": today}, {"_id": 0}).to_list(1000)
    total_milk_today = sum(m.get('total_liters', 0) for m in today_milk)
    
    # Monthly revenue
    monthly_sales = await db.sales.find({}, {"_id": 0}).to_list(1000)
    monthly_sales_filtered = [s for s in monthly_sales if s.get('date', '').startswith(current_month)]
    total_revenue_month = sum(s.get('total_amount', 0) for s in monthly_sales_filtered)
    
    # Monthly expenses
    monthly_expenses = await db.expenses.find({}, {"_id": 0}).to_list(1000)
    monthly_expenses_filtered = [e for e in monthly_expenses if e.get('date', '').startswith(current_month)]
    total_expenses_month = sum(e.get('amount', 0) for e in monthly_expenses_filtered)
    
    # Profit/Loss
    profit_loss_month = total_revenue_month - total_expenses_month
    
    # Customer and worker counts
    total_customers = len(await db.customers.find({}, {"_id": 0}).to_list(1000))
    total_workers = len(await db.workers.find({}, {"_id": 0}).to_list(1000))
    
    return DashboardStats(
        total_animals=total_animals,
        active_animals=active_animals,
        total_milk_today=total_milk_today,
        total_revenue_month=total_revenue_month,
        total_expenses_month=total_expenses_month,
        profit_loss_month=profit_loss_month,
        total_customers=total_customers,
        total_workers=total_workers
    )

# =============== INCLUDE ROUTER ===============

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
import os

import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
